import 'reflect-metadata';
import { webcrypto } from 'node:crypto';
import { request } from 'node:https';
import type { AddressInfo } from 'node:net';
import * as x509 from '@peculiar/x509';
import type { FastifyInstance } from 'fastify';
import { buildAgentServer } from '../src/agent/server.ts';
import { bearer, type TestCtx } from './helpers.ts';

const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;

export interface AgentKey {
  keyPem: string;
  csrPem: string;
}

/** What the Go agent does: fresh P-256 key + CSR. */
export async function newAgentKey(cn = 'ignored-by-server'): Promise<AgentKey> {
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ['sign', 'verify'])) as CryptoKeyPair;
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({ name: `CN=${cn}`, keys, signingAlgorithm: ALG });
  const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey)).toString('base64');
  return { keyPem: `-----BEGIN PRIVATE KEY-----\n${pkcs8.replace(/(.{64})/g, '$1\n')}\n-----END PRIVATE KEY-----\n`, csrPem: csr.toString('pem') };
}

export interface EnrolledAgent {
  deviceId: string;
  keyPem: string;
  certPem: string;
  caPem: string;
}

export async function createEnrollmentToken(ctx: TestCtx, body: Record<string, unknown> = { name: 'test' }) {
  const res = await ctx.app.inject({ method: 'POST', url: '/api/v1/enrollment-tokens', headers: bearer(ctx.adminToken), payload: body });
  if (res.statusCode !== 201) throw new Error(res.body);
  return res.json() as { id: string; token: string; installCommands: { windows: string; linux: string; macos: string } };
}

export async function enroll(ctx: TestCtx, token: string, opts: { machineId?: string; hostname?: string; os?: string } = {}) {
  const key = await newAgentKey();
  const res = await ctx.app.inject({
    method: 'POST',
    url: '/api/v1/agent/enroll',
    payload: {
      token,
      csr: key.csrPem,
      hostname: opts.hostname ?? 'PC-0001',
      os: opts.os ?? 'windows',
      osVersion: 'Windows 11 Pro 23H2',
      arch: 'amd64',
      agentVersion: '0.2.0',
      machineId: opts.machineId ?? `machine-${Math.random().toString(36).slice(2)}`,
    },
  });
  return { res, key };
}

export async function enrollOk(ctx: TestCtx, opts: Parameters<typeof enroll>[2] = {}): Promise<EnrolledAgent> {
  const { token } = await createEnrollmentToken(ctx);
  const { res, key } = await enroll(ctx, token, opts);
  if (res.statusCode !== 200) throw new Error(res.body);
  const body = res.json();
  return { deviceId: body.deviceId, keyPem: key.keyPem, certPem: body.certificate, caPem: body.caCertificate };
}

export interface AgentServerHandle {
  app: FastifyInstance;
  port: number;
  close(): Promise<void>;
}

export async function startAgentServer(ctx: TestCtx): Promise<AgentServerHandle> {
  const app = await buildAgentServer({ config: ctx.config, db: ctx.handle.db, pki: ctx.pki, signer: ctx.signer, logger: false });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const port = (app.server.address() as AddressInfo).port;
  return { app, port, close: () => app.close() };
}

export interface AgentResponse {
  status: number;
  body: any;
}

type Creds = { certPem?: string; keyPem?: string; caPem: string };

/** HTTPS request to the agent endpoint, optionally with a client certificate (like the Go agent). */
export function agentCall(
  method: 'GET' | 'POST',
  port: number,
  path: string,
  body: unknown,
  creds: Creds,
  extraHeaders: Record<string, string> = {},
): Promise<AgentResponse & { raw: Buffer; headers: Record<string, string | string[] | undefined> }> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = request(
      {
        host: '127.0.0.1',
        servername: 'localhost',
        port,
        path,
        method,
        ca: creds.caPem,
        cert: creds.certPem,
        key: creds.keyPem,
        headers: { ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}), ...extraHeaders },
        agent: false,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks);
          const text = raw.toString('utf8');
          const json = (res.headers['content-type'] ?? '').includes('application/json');
          resolve({ status: res.statusCode ?? 0, body: text && json ? JSON.parse(text) : null, raw, headers: res.headers });
        });
      },
    );
    req.on('error', reject);
    req.end(payload);
  });
}

export function agentRequest(port: number, path: string, body: unknown, creds: Creds): Promise<AgentResponse> {
  return agentCall('POST', port, path, body, creds);
}

/** Synthetic inventory (no real host data in the repo). */
export function sampleInventory(overrides: Record<string, unknown> = {}) {
  return {
    collectedAt: new Date().toISOString(),
    hardware: {
      manufacturer: 'Contoso',
      model: 'Workstation 5000',
      serialNumber: 'SN-TEST-0001',
      chassis: 'Desktop',
      biosVendor: 'Contoso BIOS',
      biosVersion: '1.0.0',
      biosDate: '2025-01-15',
      cpu: { model: 'Example CPU 8-Core', cores: 8, logicalProcessors: 16, mhz: 3200 },
      memoryBytes: 34359738368,
    },
    os: { name: 'Windows 11 Pro', version: '10.0.22631', build: '22631', arch: '64-bit', installDate: '2025-02-01T08:00:00Z', lastBoot: '2026-11-12T07:00:00Z' },
    disks: [{ name: 'C:', mount: 'C:\\', fsType: 'NTFS', sizeBytes: 512000000000, freeBytes: 200000000000 }],
    network: [{ name: 'Ethernet', mac: '00:11:22:33:44:55', up: true, ipv4: ['10.0.0.10'], ipv6: [] }],
    software: [
      { name: '7-Zip 23.01 (x64)', version: '23.01', publisher: 'Igor Pavlov', installDate: '2025-03-01', source: 'registry', arch: 'x64' },
      { name: 'Mozilla Firefox', version: '131.0', publisher: 'Mozilla', installDate: '2025-10-01', source: 'registry', arch: 'x64' },
    ],
    patches: [{ id: 'KB5031455', description: 'Update', installedOn: '2025-10-10' }],
    services: [{ name: 'Spooler', displayName: 'Print Spooler', state: 'Running', startMode: 'Auto' }],
    autostart: [{ name: 'OneDrive', command: 'C:\\OneDrive.exe /background', location: 'HKU\\Run' }],
    localUsers: [{ name: 'Administrator', fullName: '', disabled: true, uid: 'S-1-5-21-1-500' }],
    localGroups: [{ name: 'Administrators', members: ['Administrator'] }],
    loggedOnUsers: ['CONTOSO\\max'],
    ...overrides,
  };
}
