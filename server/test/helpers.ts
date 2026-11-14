import { randomBytes } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app.ts';
import { loadConfig, type Config } from '../src/config.ts';
import { connectPglite, connectPostgres, type DbHandle } from '../src/db/client.ts';
import { initPki, type Pki } from '../src/pki/ca.ts';
import { initSigner, type Signer } from '../src/pki/signing.ts';
import type { Directory } from '../src/auth/ldap.ts';
import type { DeliverDeps } from '../src/webhooks/deliver.ts';
import { ensureSeed } from '../src/seed.ts';

export const ADMIN = { username: 'admin', password: 'admin-password-123' };

export type TestApp = FastifyInstance;

export interface TestCtx {
  app: TestApp;
  handle: DbHandle;
  config: Config;
  pki: Pki;
  signer: Signer;
  adminToken: string;
  close(): Promise<void>;
}

const silent = { info: () => {}, warn: () => {} };

/**
 * PGlite (in-process) by default. With TEST_DATABASE_URL set (CI), every test file
 * gets its own throw-away database on a real PostgreSQL server.
 */
async function connectTestDb(): Promise<DbHandle> {
  const url = process.env.TEST_DATABASE_URL;
  if (!url) return connectPglite();
  const { default: postgres } = await import('postgres');
  const admin = postgres(url, { max: 1, onnotice: () => {} });
  const name = `opencm_test_${randomBytes(6).toString('hex')}`;
  await admin.unsafe(`CREATE DATABASE ${name}`);
  const dbUrl = new URL(url);
  dbUrl.pathname = `/${name}`;
  const handle = await connectPostgres(dbUrl.toString());
  return {
    ...handle,
    async close() {
      await handle.close();
      await admin.unsafe(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      await admin.end();
    },
  };
}

export async function setup(overrides: Partial<Record<keyof Config, string>> = {}, opts: { directory?: Directory | null; webhookDeps?: DeliverDeps } = {}): Promise<TestCtx> {
  const tmp = mkdtempSync(join(tmpdir(), 'opencm-test-'));
  const config = loadConfig({
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    PUBLIC_URL: 'https://cm.test.local',
    LOGIN_RATE_LIMIT_PER_MIN: '1000',
    ENROLL_RATE_LIMIT_PER_MIN: '1000',
    BOOTSTRAP_ADMIN_USER: ADMIN.username,
    BOOTSTRAP_ADMIN_PASSWORD: ADMIN.password,
    PKI_DIR: join(tmp, 'pki'),
    AGENT_DOWNLOAD_DIR: join(tmp, 'agent'),
    PACKAGE_DIR: join(tmp, 'packages'),
    PATCH_SCAN_INTERVAL_HOURS: '0',
    ...overrides,
  });
  const handle = await connectTestDb();
  await handle.migrate();
  await ensureSeed(handle.db, config, silent);
  const pki = await initPki(config.PKI_DIR, ['localhost', '127.0.0.1']);
  const signer = await initSigner(config.PKI_DIR);
  const app = await buildApp({ config, db: handle.db, pki, signer, directory: opts.directory ?? null, webhookDeps: opts.webhookDeps, logger: false });
  await app.ready();
  const adminToken = await login(app, ADMIN.username, ADMIN.password);
  return {
    app,
    handle,
    config,
    pki,
    signer,
    adminToken,
    async close() {
      await app.close();
      await handle.close();
    },
  };
}

export async function login(app: TestApp, username: string, password: string): Promise<string> {
  const res = await app.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { username, password } });
  if (res.statusCode !== 200) throw new Error(`login failed for ${username}: ${res.statusCode} ${res.body}`);
  return res.json().token;
}

export const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

/** Create a role with the given grants and a user holding it; returns the user's token. */
export async function userWithGrants(ctx: TestCtx, name: string, permissions: string[]) {
  const role = await ctx.app.inject({
    method: 'POST',
    url: '/api/v1/roles',
    headers: bearer(ctx.adminToken),
    payload: { name: `role-${name}`, permissions },
  });
  if (role.statusCode !== 201) throw new Error(role.body);
  const password = 'user-password-123';
  const user = await ctx.app.inject({
    method: 'POST',
    url: '/api/v1/users',
    headers: bearer(ctx.adminToken),
    payload: { username: name, password, roleIds: [role.json().id] },
  });
  if (user.statusCode !== 201) throw new Error(user.body);
  return { userId: user.json().id as string, roleId: role.json().id as string, token: await login(ctx.app, name, password) };
}
