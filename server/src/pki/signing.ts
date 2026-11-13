import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto';
import { chmod, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * Ed25519 key used to sign everything the agent executes (task envelopes, agent
 * updates). Agents receive the public key during enrolment and refuse anything
 * that does not verify against it.
 */
export interface Signer {
  /** raw 32-byte public key, base64 (what the Go agent stores) */
  publicKey: string;
  sign(data: Buffer): string;
  verify(data: Buffer, signatureB64: string): boolean;
  /** JSON payload → { payload: base64(bytes), signature: base64(sig over bytes) } */
  envelope(obj: unknown): SignedEnvelope;
}

export interface SignedEnvelope {
  payload: string;
  signature: string;
}

function rawPublicKey(pub: KeyObject): string {
  const jwk = pub.export({ format: 'jwk' }) as { x: string };
  return Buffer.from(jwk.x, 'base64url').toString('base64');
}

export async function initSigner(dir: string): Promise<Signer> {
  const keyPath = join(dir, 'signing.key');
  let privateKey: KeyObject;
  let pem: string | null = null;
  try {
    pem = await readFile(keyPath, 'utf8');
  } catch (err) {
    // Only a missing file means "first start". Agents pin the public key at enrolment: a silently
    // regenerated key would make the whole fleet refuse every task and update (REV-010).
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error(`signing.key is unreadable: ${(err as Error).message}`);
  }
  if (pem !== null) {
    try {
      privateKey = createPrivateKey(pem);
    } catch (err) {
      throw new Error(`signing.key is damaged (${(err as Error).message}) – restore it from the backup of the pki volume; it is not regenerated automatically`);
    }
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('signing.key is not an Ed25519 key – restore it from the backup of the pki volume');
  } else {
    const pair = generateKeyPairSync('ed25519');
    privateKey = pair.privateKey;
    const tmp = `${keyPath}.tmp`;
    await writeFile(tmp, privateKey.export({ format: 'pem', type: 'pkcs8' }) as string, { mode: 0o600 });
    await chmod(tmp, 0o600).catch(() => {});
    await rename(tmp, keyPath);
  }
  const publicKey = createPublicKey(privateKey);
  const signer: Signer = {
    publicKey: rawPublicKey(publicKey),
    sign: (data) => sign(null, data, privateKey).toString('base64'),
    verify: (data, sig) => verify(null, data, publicKey, Buffer.from(sig, 'base64')),
    envelope(obj) {
      const bytes = Buffer.from(JSON.stringify(obj), 'utf8');
      return { payload: bytes.toString('base64'), signature: signer.sign(bytes) };
    },
  };
  return signer;
}

/** Message signed for agent self-updates. Must match agent/internal/updater. */
export function updateMessage(os: string, arch: string, version: string, sha256: string): Buffer {
  return Buffer.from(`opencm-agent-update:v1:${os}:${arch}:${version}:${sha256}`, 'utf8');
}
