import 'reflect-metadata';
import { createHash, randomBytes, webcrypto } from 'node:crypto';
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join } from 'node:path';
import * as x509 from '@peculiar/x509';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;
const DAY = 86_400_000;
const CA_YEARS = 20;
const SERVER_CERT_DAYS = 397;
const RENEW_SERVER_BEFORE_DAYS = 30;

export interface IssuedCert {
  pem: string;
  fingerprint: string; // sha256 hex of DER, lowercase, no separators
  serial: string;
  notAfter: Date;
}

export interface Pki {
  caCertPem: string;
  serverCertPem: string;
  serverKeyPem: string;
  /** Verifies a PKCS#10 CSR and issues a client certificate with CN=<deviceId>. */
  signClientCsr(csrPem: string, deviceId: string, days: number): Promise<IssuedCert>;
}

export class CsrError extends Error {}

export function fingerprintOfDer(der: ArrayBuffer | Uint8Array): string {
  return createHash('sha256').update(new Uint8Array(der)).digest('hex');
}

/** Node's `getPeerCertificate().fingerprint256` → our format */
export function normalizeFingerprint(fp: string): string {
  return fp.replace(/:/g, '').toLowerCase();
}

function serial(): string {
  const b = randomBytes(16);
  b[0] = b[0]! & 0x7f; // positive
  return b.toString('hex');
}

function toPem(der: ArrayBuffer, label: string): string {
  const b64 = Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN ${label}-----\n${b64.trim()}\n-----END ${label}-----\n`;
}

function fromPem(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----(BEGIN|END)[^-]+-----/g, '').replace(/\s+/g, '');
  const buf = Buffer.from(b64, 'base64');
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

async function exists(path: string): Promise<boolean> {
  try {
    await readFile(path);
    return true;
  } catch {
    return false;
  }
}

async function writeSecret(path: string, content: string) {
  const tmp = `${path}.tmp`;
  await writeFile(tmp, content, { mode: 0o600 });
  await chmod(tmp, 0o600).catch(() => {}); // no-op on Windows
  await rename(tmp, path);
}

interface CaMaterial {
  cert: x509.X509Certificate;
  keys: CryptoKeyPair;
}

async function loadOrCreateCa(dir: string): Promise<CaMaterial> {
  const certPath = join(dir, 'ca.crt');
  const keyPath = join(dir, 'ca.key');
  if ((await exists(certPath)) && (await exists(keyPath))) {
    const cert = new x509.X509Certificate(await readFile(certPath, 'utf8'));
    const privateKey = await webcrypto.subtle.importKey('pkcs8', fromPem(await readFile(keyPath, 'utf8')), ALG, true, ['sign']);
    const publicKey = await cert.publicKey.export(ALG, ['verify']);
    return { cert, keys: { privateKey, publicKey } as CryptoKeyPair };
  }
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const now = new Date();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(),
    name: 'CN=OpenCM Agent CA, O=OpenCM',
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + CA_YEARS * 365 * DAY),
    keys,
    signingAlgorithm: ALG,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });
  await writeSecret(keyPath, toPem(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY'));
  await writeFile(certPath, cert.toString('pem') + '\n');
  return { cert, keys };
}

async function issueServerCert(ca: CaMaterial, hostnames: string[]) {
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const now = new Date();
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial(),
    subject: `CN=${hostnames[0] ?? 'opencm'}`,
    issuer: ca.cert.subject,
    notBefore: new Date(now.getTime() - DAY),
    notAfter: new Date(now.getTime() + SERVER_CERT_DAYS * DAY),
    publicKey: keys.publicKey,
    signingKey: ca.keys.privateKey,
    signingAlgorithm: ALG,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
      new x509.SubjectAlternativeNameExtension(hostnames.map((h) => ({ type: isIP(h) ? 'ip' : 'dns', value: h }) as const)),
      await x509.AuthorityKeyIdentifierExtension.create(ca.cert),
    ],
  });
  return { cert, keyPem: toPem(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY') };
}

function sanNames(cert: x509.X509Certificate): string[] {
  const ext = cert.getExtension(x509.SubjectAlternativeNameExtension);
  return ext ? ext.names.items.map((n) => n.value).sort() : [];
}

async function loadOrRenewServerCert(dir: string, ca: CaMaterial, hostnames: string[]) {
  const certPath = join(dir, 'agent-endpoint.crt');
  const keyPath = join(dir, 'agent-endpoint.key');
  if ((await exists(certPath)) && (await exists(keyPath))) {
    const pem = await readFile(certPath, 'utf8');
    const cert = new x509.X509Certificate(pem);
    const fresh = cert.notAfter.getTime() - Date.now() > RENEW_SERVER_BEFORE_DAYS * DAY;
    const sameNames = JSON.stringify(sanNames(cert)) === JSON.stringify([...hostnames].sort());
    const sameIssuer = await cert.verify({ publicKey: ca.keys.publicKey, signatureOnly: true }).catch(() => false);
    if (fresh && sameNames && sameIssuer) return { certPem: pem, keyPem: await readFile(keyPath, 'utf8') };
  }
  const { cert, keyPem } = await issueServerCert(ca, hostnames);
  const certPem = cert.toString('pem') + '\n';
  await writeSecret(keyPath, keyPem);
  await writeFile(certPath, certPem);
  return { certPem, keyPem };
}

/**
 * Loads the agent CA from `dir` (creating it on first start) and makes sure a valid
 * server certificate for the agent endpoint exists for `hostnames`.
 */
export async function initPki(dir: string, hostnames: string[]): Promise<Pki> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const ca = await loadOrCreateCa(dir);
  const server = await loadOrRenewServerCert(dir, ca, hostnames);
  const caCertPem = ca.cert.toString('pem') + '\n';

  return {
    caCertPem,
    serverCertPem: server.certPem,
    serverKeyPem: server.keyPem,

    async signClientCsr(csrPem, deviceId, days) {
      let csr: x509.Pkcs10CertificateRequest;
      try {
        csr = new x509.Pkcs10CertificateRequest(csrPem);
      } catch {
        throw new CsrError('CSR is not a valid PKCS#10 request');
      }
      const alg = csr.publicKey.algorithm as { name: string; namedCurve?: string; modulusLength?: number };
      const okKey =
        (alg.name === 'ECDSA' && ['P-256', 'P-384'].includes(alg.namedCurve ?? '')) ||
        (alg.name === 'RSASSA-PKCS1-v1_5' && (alg.modulusLength ?? 0) >= 2048);
      if (!okKey) throw new CsrError('Unsupported key type (use ECDSA P-256/P-384 or RSA >= 2048)');
      if (!(await csr.verify())) throw new CsrError('CSR signature is invalid');

      const now = new Date();
      const notAfter = new Date(now.getTime() + days * DAY);
      const sn = serial();
      // The requested subject is ignored: identity is assigned by the server.
      const cert = await x509.X509CertificateGenerator.create({
        serialNumber: sn,
        subject: `CN=${deviceId}, O=OpenCM Devices`,
        issuer: ca.cert.subject,
        notBefore: new Date(now.getTime() - 5 * 60_000),
        notAfter,
        publicKey: csr.publicKey,
        signingKey: ca.keys.privateKey,
        signingAlgorithm: ALG,
        extensions: [
          new x509.BasicConstraintsExtension(false, undefined, true),
          new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
          new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth]),
          await x509.AuthorityKeyIdentifierExtension.create(ca.cert),
        ],
      });
      return { pem: cert.toString('pem') + '\n', fingerprint: fingerprintOfDer(cert.rawData), serial: sn, notAfter };
    },
  };
}
