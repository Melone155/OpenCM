import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import type { TLSSocket } from 'node:tls';
import { and, eq, inArray, sql } from 'drizzle-orm';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { ZodError, z } from 'zod';
import type { RegisteredRoute } from '../app.ts';
import { writeAudit } from '../audit.ts';
import type { Config } from '../config.ts';
import type { Db } from '../db/client.ts';
import { devices, jobRuns, tasks } from '../db/schema.ts';
import { PackageStore } from '../packages/storage.ts';
import { BandwidthLimiter } from '../packages/throttle.ts';
import { HttpError, parse, Uuid } from '../http.ts';
import { ingestInventory } from '../inventory/ingest.ts';
import { InventorySchema } from '../inventory/schema.ts';
import { appendOutput, applyResult, claimNextTask, fireDeviceTriggers, markStarted } from '../jobs/engine.ts';
import { CsrError, normalizeFingerprint, type Pki } from '../pki/ca.ts';
import { updateMessage, type Signer } from '../pki/signing.ts';
import { lenientJson } from '../plugins/json.ts';
import { AgentBinaries } from './binaries.ts';

export const AGENT_PREFIX = '/agent/v1';
const RENEW_BEFORE_DAYS = 30;
const LONG_POLL_INTERVAL_MS = 1000;

export interface AgentIdentity {
  deviceId: string;
  hostname: string;
  os: string;
  arch: string;
  loggedOnUser: string | null;
  certExpiresAt: Date | null;
}

declare module 'fastify' {
  interface FastifyRequest {
    device: AgentIdentity | null;
  }
}

const Heartbeat = z.object({
  agentVersion: z.string().max(50),
  hostname: z.string().max(255).optional(),
  loggedOnUsers: z.array(z.string().max(255)).max(100).optional(),
  uptimeSeconds: z.number().nonnegative().optional(),
  agentStarted: z.boolean().optional(),
});
const Renew = z.object({ csr: z.string().min(1).max(20_000) });
const TaskParams = z.object({ id: Uuid });
const FileParams = z.object({ sha256: z.string().regex(/^[0-9a-f]{64}$/) });
const NextQuery = z.object({ wait: z.coerce.number().int().min(0).max(30).default(0) });
const Output = z.object({
  chunks: z.array(z.object({ stream: z.enum(['stdout', 'stderr']), data: z.string().max(1024 * 1024) })).max(100),
});
const StepResultSchema = z.object({
  position: z.number().int().min(0),
  status: z.enum(['succeeded', 'failed', 'skipped', 'timeout', 'cancelled']),
  exitCode: z.number().int().nullable(),
  durationMs: z.number().int().min(0),
  stdoutTail: z.string().max(8192).optional(),
});
const Result = z.object({
  status: z.enum(['succeeded', 'failed', 'timeout', 'cancelled']),
  exitCode: z.number().int().nullable().default(null),
  error: z.string().max(2000).nullable().optional(),
  steps: z.array(StepResultSchema).max(100).default([]),
});

export interface AgentServerOptions {
  config: Config;
  db: Db;
  pki: Pki;
  signer: Signer;
  logger?: boolean;
}

/**
 * Splits "a, b" into a set of normalised user names (logged-on users are stored comma
 * separated). The domain part is dropped and case ignored: the Windows inventory reports
 * "CONTOSO\max", the heartbeat (quser) just "max" – both must count as the same session.
 */
const userSet = (s: string | null | undefined) =>
  new Set(
    (s ?? '')
      .split(',')
      .map((x) => x.trim().split('\\').pop()!.toLowerCase())
      .filter(Boolean),
  );

/**
 * HTTPS listener for agents. TLS requires a client certificate issued by our CA;
 * each request is additionally matched against the device's stored certificate
 * fingerprint, so revocation/re-enrolment takes effect immediately.
 */
export async function buildAgentServer({ config, db, pki, signer, logger = true }: AgentServerOptions): Promise<FastifyInstance> {
  const binaries = new AgentBinaries(config.AGENT_DOWNLOAD_DIR);
  const store = new PackageStore(config.PACKAGE_DIR);
  const limiter = new BandwidthLimiter(config.PACKAGE_BANDWIDTH_KBPS, config.PACKAGE_BANDWIDTH_PER_DEVICE_KBPS);
  const app = Fastify({
    logger: logger && { level: config.LOG_LEVEL, redact: ['req.headers.authorization'] },
    https: {
      key: pki.serverKeyPem,
      cert: pki.serverCertPem,
      ca: [pki.caCertPem],
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
    },
    bodyLimit: 32 * 1024 * 1024, // large software inventories
    trustProxy: false,
  });

  const routes: RegisteredRoute[] = [];
  app.decorate('registeredRoutes', routes);
  app.addHook('onRoute', (r) => {
    for (const m of [r.method].flat()) if (m !== 'HEAD') routes.push({ method: m, url: r.url });
  });
  app.decorateRequest('device', null);
  lenientJson(app);

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof ZodError) return reply.code(400).send({ error: { code: 'validation_error', message: 'Invalid request', details: err.issues } });
    if (err instanceof HttpError) return reply.code(err.statusCode).send({ error: { code: err.code, message: err.message } });
    const e = err as { statusCode?: number; message: string };
    if ((e.statusCode ?? 500) >= 500) req.log.error({ err }, 'agent endpoint error');
    return reply.code(e.statusCode ?? 500).send({ error: { code: 'error', message: (e.statusCode ?? 500) >= 500 ? 'Internal server error' : e.message } });
  });

  app.addHook('onRequest', async (req) => {
    req.device = await identify(db, req);
  });

  const device = (req: FastifyRequest): AgentIdentity => {
    if (!req.device) throw new HttpError(403, 'device_not_authorized', 'Unknown or revoked device certificate');
    return req.device;
  };

  async function updateOffer(d: AgentIdentity, agentVersion: string) {
    if (!config.AGENT_AUTO_UPDATE || agentVersion === 'dev') return null;
    const { version, binary } = await binaries.find(d.os, d.arch);
    if (!version || !binary || version === agentVersion) return null;
    return {
      version,
      sha256: binary.sha256,
      sizeBytes: binary.sizeBytes,
      signature: signer.sign(updateMessage(d.os, d.arch, version, binary.sha256)),
    };
  }

  await app.register(
    async (api) => {
      api.post('/heartbeat', async (req) => {
        const d = device(req);
        const body = parse(Heartbeat, req.body);
        const now = new Date();
        const before = userSet(d.loggedOnUser);
        const loggedOn = body.loggedOnUsers?.join(', ') || null;
        const [row] = await db
          .update(devices)
          .set({
            lastSeenAt: now,
            lastIp: req.ip,
            agentVersion: body.agentVersion,
            ...(body.hostname && { hostname: body.hostname }),
            ...(body.loggedOnUsers && { loggedOnUser: loggedOn }),
            ...(body.agentStarted && { agentStartedAt: now }),
          })
          .where(eq(devices.id, d.deviceId))
          .returning({ inventoryRequested: devices.inventoryRequested });

        const newLogins = body.loggedOnUsers ? [...userSet(loggedOn)].filter((u) => !before.has(u)) : [];
        const runs = await fireDeviceTriggers(db, config, d.deviceId, { agentStarted: !!body.agentStarted, newLogins });
        if (runs.length) req.log.info({ deviceId: d.deviceId, runs, newLogins, agentStarted: body.agentStarted }, 'device triggers fired');

        const renew = !!d.certExpiresAt && d.certExpiresAt.getTime() - Date.now() < RENEW_BEFORE_DAYS * 86_400_000;
        return {
          serverTime: now.toISOString(),
          heartbeatSeconds: config.AGENT_HEARTBEAT_SECONDS,
          inventoryRequested: row?.inventoryRequested ?? false,
          renewCertificate: renew,
          update: await updateOffer(d, body.agentVersion),
        };
      });

      api.post('/inventory', async (req, reply) => {
        const d = device(req);
        const inv = parse(InventorySchema, req.body);
        const { changes } = await ingestInventory(db, d.deviceId, inv, { maxSignatureAgeDays: config.SECURITY_AV_MAX_AGE_DAYS });
        req.log.info({ deviceId: d.deviceId, software: inv.software.length, changes }, 'inventory received');
        return reply.code(204).send();
      });

      api.post('/certificate/renew', async (req) => {
        const d = device(req);
        const { csr } = parse(Renew, req.body);
        let issued;
        try {
          issued = await pki.signClientCsr(csr, d.deviceId, config.AGENT_CERT_DAYS);
        } catch (err) {
          if (err instanceof CsrError) throw new HttpError(400, 'invalid_csr', err.message);
          throw err;
        }
        await db
          .update(devices)
          .set({ certFingerprint: issued.fingerprint, certSerial: issued.serial, certExpiresAt: issued.notAfter, updatedAt: new Date() })
          .where(eq(devices.id, d.deviceId));
        await writeAudit(db, { type: 'agent', id: d.deviceId, name: d.hostname }, {
          action: 'device.certificate_renew',
          targetType: 'device',
          targetId: d.deviceId,
          details: { serial: issued.serial, notAfter: issued.notAfter.toISOString() },
          ip: req.ip,
        });
        return { certificate: issued.pem, caCertificate: pki.caCertPem, expiresAt: issued.notAfter.toISOString() };
      });

      api.get('/signing-key', async (req) => {
        device(req);
        return { algorithm: 'ed25519', publicKey: signer.publicKey };
      });

      // Long poll: returns a signed task envelope as soon as one is runnable, or 204 after `wait` seconds.
      api.get('/tasks/next', async (req, reply) => {
        const d = device(req);
        const { wait } = parse(NextQuery, req.query);
        let closed = false;
        reply.raw.on('close', () => (closed = true));
        const deadline = Date.now() + wait * 1000;
        for (;;) {
          const envelope = await claimNextTask(db, signer, d.deviceId);
          if (envelope) {
            if (closed) {
              // client gone before delivery: hand the task back
              const payload = JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8')) as { taskId: string };
              await db.update(tasks).set({ status: 'pending', dispatchedAt: null }).where(and(eq(tasks.id, payload.taskId), eq(tasks.status, 'dispatched')));
              return reply;
            }
            return envelope;
          }
          if (closed || Date.now() >= deadline) return reply.code(204).send();
          await new Promise((r) => setTimeout(r, Math.min(LONG_POLL_INTERVAL_MS, Math.max(0, deadline - Date.now()))));
        }
      });

      api.post('/tasks/:id/start', async (req) => {
        const d = device(req);
        const { id } = parse(TaskParams, req.params);
        return markStarted(db, d.deviceId, id);
      });

      api.post('/tasks/:id/output', async (req) => {
        const d = device(req);
        const { id } = parse(TaskParams, req.params);
        const { chunks } = parse(Output, req.body);
        return appendOutput(db, config, d.deviceId, id, chunks);
      });

      api.post('/tasks/:id/result', async (req, reply) => {
        const d = device(req);
        const { id } = parse(TaskParams, req.params);
        const result = parse(Result, req.body);
        await applyResult(db, d.deviceId, id, result);
        return reply.code(204).send();
      });

      // Installer files of package steps. Only files belonging to a task that is currently
      // dispatched to / running on this device; resumable via Range; bandwidth limited.
      api.get('/files/:sha256', async (req, reply) => {
        const d = device(req);
        const { sha256 } = parse(FileParams, req.params);
        const [assigned] = await db
          .select({ id: tasks.id })
          .from(tasks)
          .innerJoin(jobRuns, eq(jobRuns.id, tasks.runId))
          .where(
            and(
              eq(tasks.deviceId, d.deviceId),
              inArray(tasks.status, ['dispatched', 'running']),
              sql`${jobRuns.steps} @> ${JSON.stringify([{ files: [{ sha256 }] }])}::jsonb`,
            ),
          )
          .limit(1);
        if (!assigned) throw new HttpError(404, 'not_found', 'File not assigned to an active task of this device');
        const path = store.path(sha256);
        let size: number;
        try {
          size = (await stat(path)).size;
        } catch {
          throw new HttpError(404, 'not_found', 'File missing in the package repository');
        }
        let start = 0;
        let end = size - 1;
        const range = req.headers.range;
        if (range) {
          const m = /^bytes=(\d+)-(\d*)$/.exec(range.trim());
          if (!m) throw new HttpError(416, 'range_not_satisfiable', 'Only single byte ranges are supported');
          start = Number(m[1]);
          if (m[2]) end = Math.min(Number(m[2]), size - 1);
          if (start > end || start >= size) {
            return reply.code(416).header('content-range', `bytes */${size}`).send({ error: { code: 'range_not_satisfiable', message: 'Range outside the file' } });
          }
          reply.code(206).header('content-range', `bytes ${start}-${end}/${size}`);
        }
        const { stream, release } = limiter.acquire(d.deviceId);
        const file = createReadStream(path, { start, end });
        const done = () => {
          release();
          file.destroy();
        };
        stream.on('close', done);
        stream.on('error', done);
        reply.raw.on('close', done);
        return reply
          .header('content-type', 'application/octet-stream')
          .header('content-length', end - start + 1)
          .header('accept-ranges', 'bytes')
          .header('x-checksum-sha256', sha256)
          .send(file.pipe(stream));
      });

      api.get('/update/download', async (req, reply) => {
        const d = device(req);
        const { binary } = await binaries.find(d.os, d.arch);
        if (!binary) throw new HttpError(404, 'not_found', `No agent binary for ${d.os}/${d.arch}`);
        return reply
          .header('content-type', 'application/octet-stream')
          .header('content-length', binary.sizeBytes)
          .header('x-checksum-sha256', binary.sha256)
          .send(createReadStream(binary.path));
      });
    },
    { prefix: AGENT_PREFIX },
  );

  return app;
}

async function identify(db: Db, req: FastifyRequest): Promise<AgentIdentity | null> {
  const socket = req.raw.socket as TLSSocket;
  if (!socket.authorized) return null;
  const cert = socket.getPeerCertificate();
  if (!cert?.fingerprint256) return null;
  const [row] = await db
    .select({
      id: devices.id,
      hostname: devices.hostname,
      os: devices.os,
      arch: devices.arch,
      loggedOnUser: devices.loggedOnUser,
      certExpiresAt: devices.certExpiresAt,
    })
    .from(devices)
    .where(and(eq(devices.certFingerprint, normalizeFingerprint(cert.fingerprint256)), eq(devices.status, 'active')));
  return row
    ? { deviceId: row.id, hostname: row.hostname, os: row.os, arch: row.arch, loggedOnUser: row.loggedOnUser, certExpiresAt: row.certExpiresAt }
    : null;
}
