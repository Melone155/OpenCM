import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import cookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import Fastify, { type FastifyInstance } from 'fastify';
import { ZodError } from 'zod';
import type { Config } from './config.ts';
import type { Db } from './db/client.ts';
import { HttpError } from './http.ts';
import { registerAuth } from './plugins/auth.ts';
import { lenientJson } from './plugins/json.ts';
import { AgentBinaries } from './agent/binaries.ts';
import { createLdapDirectory, type Directory } from './auth/ldap.ts';
import { initSecretBox } from './auth/secretbox.ts';
import { initIntegrityKey, sealUnsealedScriptVersions } from './integrity.ts';
import { securityRoutes } from './routes/security.ts';
import type { Pki } from './pki/ca.ts';
import type { Signer } from './pki/signing.ts';
import { customFieldRoutes } from './routes/custom-fields.ts';
import { deviceGroupRoutes } from './routes/device-groups.ts';
import { jobRoutes } from './routes/jobs.ts';
import { scriptRoutes } from './routes/scripts.ts';
import { vulnerabilityRoutes } from './routes/vulnerabilities.ts';
import { deploymentRoutes } from './routes/deployments.ts';
import { packageRoutes } from './routes/packages.ts';
import { patchRoutes } from './routes/patches.ts';
import { insightRoutes } from './routes/insights.ts';
import { licenseRoutes } from './routes/licenses.ts';
import { webhookRoutes } from './routes/webhooks.ts';
import { assetRoutes } from './routes/assets.ts';
import { postureRoutes } from './routes/posture.ts';
import type { DeliverDeps } from './webhooks/deliver.ts';
import { auditRoutes } from './routes/audit.ts';
import { authRoutes } from './routes/auth.ts';
import { deviceRoutes } from './routes/devices.ts';
import { downloadRoutes } from './routes/downloads.ts';
import { enrollmentRoutes } from './routes/enrollment.ts';
import { groupRoutes } from './routes/groups.ts';
import { healthRoutes } from './routes/health.ts';
import { roleRoutes } from './routes/roles.ts';
import { userRoutes } from './routes/users.ts';

export const API_PREFIX = '/api/v1';
export const OPENAPI_PATH = fileURLToPath(new URL('../openapi.yaml', import.meta.url));

export interface RegisteredRoute {
  method: string;
  url: string;
}

declare module 'fastify' {
  interface FastifyInstance {
    /** All routes registered on this instance (used by the OpenAPI contract test). */
    registeredRoutes: RegisteredRoute[];
  }
}

export interface BuildOptions {
  config: Config;
  db: Db;
  pki: Pki;
  signer: Signer;
  /** LDAP directory; default from config (LDAP_URL), null = disabled */
  directory?: Directory | null;
  /** HTTP/DNS for webhook test deliveries (tests inject fakes) */
  webhookDeps?: DeliverDeps;
  logger?: boolean;
}

export async function buildApp({ config, db, pki, signer, directory, webhookDeps, logger = true }: BuildOptions): Promise<FastifyInstance> {
  const secretBox = await initSecretBox(config.PKI_DIR);
  await initIntegrityKey(config.PKI_DIR);
  await sealUnsealedScriptVersions(db);
  const dir = directory === undefined ? createLdapDirectory(config) : directory;
  const app = Fastify({
    logger: logger && {
      level: config.LOG_LEVEL,
      redact: ['req.headers.authorization', 'req.headers.cookie', 'res.headers["set-cookie"]', '*.password'],
    },
    trustProxy: true,
    bodyLimit: 1024 * 1024,
  });

  const routes: RegisteredRoute[] = [];
  app.decorate('registeredRoutes', routes);
  app.addHook('onRoute', (r) => {
    for (const m of [r.method].flat()) if (m !== 'HEAD') routes.push({ method: m, url: r.url });
  });

  app.decorate('db', db);
  lenientJson(app);
  await app.register(helmet, { contentSecurityPolicy: false }); // pure JSON API; UI CSP is set by the web container
  await app.register(cookie);
  await app.register(rateLimit, { global: true, max: 600, timeWindow: '1 minute' });
  await app.register(swagger, { mode: 'static', specification: { path: OPENAPI_PATH, baseDir: '' } });
  await app.register(swaggerUi, {
    routePrefix: '/api/docs',
    logo: { type: 'image/svg+xml', content: readFileSync(new URL('./assets/logo-dark.svg', import.meta.url)), href: '/api/docs' },
    theme: {
      title: 'OpenCM API',
      favicon: [{ filename: 'favicon.svg', rel: 'icon', type: 'image/svg+xml', sizes: 'any', content: readFileSync(new URL('./assets/icon.svg', import.meta.url)) }],
    },
  });

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof ZodError) {
      return reply.code(400).send({ error: { code: 'validation_error', message: 'Invalid request', details: err.issues } });
    }
    if (err instanceof HttpError) {
      return reply.code(err.statusCode).send({ error: { code: err.code, message: err.message, details: err.details } });
    }
    const e = err as { statusCode?: number; code?: string; message: string };
    const status = e.statusCode ?? 500;
    if (status >= 500) req.log.error({ err }, 'unhandled error');
    return reply.code(status).send({
      error: { code: status === 429 ? 'rate_limited' : (e.code ?? 'internal_error'), message: status >= 500 ? 'Internal server error' : e.message },
    });
  });
  app.setNotFoundHandler((_req, reply) => reply.code(404).send({ error: { code: 'not_found', message: 'Route not found' } }));

  registerAuth(app, config);

  await app.register(
    async (api: FastifyInstance) => {
      healthRoutes(api);
      authRoutes(api, config, { secretBox, directory: dir });
      securityRoutes(api, config, dir);
      userRoutes(api);
      roleRoutes(api);
      groupRoutes(api);
      auditRoutes(api);
      deviceRoutes(api, config);
      const agentBinaries = new AgentBinaries(config.AGENT_DOWNLOAD_DIR, config.AGENT_BUNDLED_DIR);
      enrollmentRoutes(api, config, pki, signer, agentBinaries);
      downloadRoutes(api, agentBinaries);
      deviceGroupRoutes(api, config);
      customFieldRoutes(api);
      scriptRoutes(api, config);
      jobRoutes(api, config);
      vulnerabilityRoutes(api, config);
      packageRoutes(api, config);
      deploymentRoutes(api, config);
      patchRoutes(api, config);
      insightRoutes(api, config);
      webhookRoutes(api, config, secretBox, webhookDeps);
      licenseRoutes(api);
      postureRoutes(api, config);
      assetRoutes(api);
    },
    { prefix: API_PREFIX },
  );

  return app;
}
