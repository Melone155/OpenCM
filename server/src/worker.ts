/**
 * Background worker (BullMQ on Redis).
 *  - scheduler: due once/cron jobs, task timeouts and retries, run completion (every 15 s)
 *  - housekeeping: expired sessions (every 15 min)
 * BullMQ job schedulers guarantee each tick runs once even with several workers;
 * the scheduler itself is additionally idempotent (optimistic claims in the DB).
 */
import { Queue, Worker } from 'bullmq';
import pino from 'pino';
import { loadConfig } from './config.ts';
import { connectPostgres } from './db/client.ts';
import { purgeExpiredSessions } from './housekeeping.ts';
import { schedulerTick } from './jobs/engine.ts';
import { initIntegrityKey } from './integrity.ts';
import { deploymentTick } from './packages/deploy.ts';
import { patchScanTick } from './patches/scan.ts';
import { defaultDeps, feedTick } from './vuln/feeds.ts';
import { initSecretBox } from './auth/secretbox.ts';
import { metricsTick } from './dashboard.ts';
import { webhookTick } from './webhooks/deliver.ts';

const config = loadConfig();
const log = pino({ level: config.LOG_LEVEL });
if (!config.DATABASE_URL) throw new Error('DATABASE_URL is required');

const handle = await connectPostgres(config.DATABASE_URL);
// runs created by the worker (schedules, rings, patch scans) are verified and sealed like on the server
await initIntegrityKey(config.PKI_DIR);
const redisUrl = new URL(config.REDIS_URL);
const connection = {
  host: redisUrl.hostname,
  port: Number(redisUrl.port || 6379),
  password: redisUrl.password || undefined,
  maxRetriesPerRequest: null,
};

const QUEUE = 'opencm-maintenance';
const queue = new Queue(QUEUE, { connection });
await queue.upsertJobScheduler('scheduler-tick', { every: 15_000 }, { name: 'scheduler-tick', opts: { removeOnComplete: true, removeOnFail: 100 } });
await queue.upsertJobScheduler('purge-sessions', { every: 15 * 60_000 }, { name: 'purge-sessions', opts: { removeOnComplete: true, removeOnFail: 100 } });
await queue.upsertJobScheduler('metrics-tick', { every: 60 * 60_000 }, { name: 'metrics-tick', opts: { removeOnComplete: true, removeOnFail: 100 } });

const worker = new Worker(
  QUEUE,
  async (job) => {
    switch (job.name) {
      case 'scheduler-tick': {
        const r = await schedulerTick(handle.db, config);
        if (r.startedRuns || r.timedOut) log.info({ job: job.name, ...r }, 'scheduler tick');
        const d = await deploymentTick(handle.db, config);
        if (d.promoted || d.paused || d.completed) log.info({ job: job.name, ...d }, 'deployment tick');
        const s = await patchScanTick(handle.db, config);
        if (s.devices) log.info({ job: job.name, devices: s.devices }, 'automatic patch scan started');
        break;
      }
      case 'purge-sessions': {
        const n = await purgeExpiredSessions(handle.db);
        log.info({ job: job.name, deleted: n }, 'expired sessions purged');
        break;
      }
      case 'metrics-tick': {
        const m = await metricsTick(handle.db, config);
        log.info({ job: job.name, day: m.day }, 'daily metrics updated');
        break;
      }
    }
  },
  { connection, concurrency: 1 },
);
worker.on('failed', (job, err) => log.error({ job: job?.name, err }, 'job failed'));

// Vulnerability feeds run in their own queue: a long NVD mirror run must not block the job scheduler.
const FEEDS_QUEUE = 'opencm-feeds';
const feedsQueue = new Queue(FEEDS_QUEUE, { connection });
await feedsQueue.upsertJobScheduler('feed-tick', { every: 60_000 }, { name: 'feed-tick', opts: { removeOnComplete: true, removeOnFail: 100 } });
const feedDeps = defaultDeps((msg, data) => log.info(data ?? {}, msg));
const feedsWorker = new Worker(
  FEEDS_QUEUE,
  async () => {
    const r = await feedTick(handle.db, config, feedDeps);
    if (r.synced.length || r.newFindings) log.info(r, 'feed tick');
  },
  { connection, concurrency: 1, lockDuration: 120_000 },
);
feedsWorker.on('failed', (job, err) => log.error({ job: job?.name, err }, 'feed job failed'));

// Webhook deliveries (outbox) in their own queue: slow receivers must not delay the scheduler.
const secretBox = await initSecretBox(config.PKI_DIR);
const HOOKS_QUEUE = 'opencm-webhooks';
const hooksQueue = new Queue(HOOKS_QUEUE, { connection });
await hooksQueue.upsertJobScheduler('webhook-tick', { every: 10_000 }, { name: 'webhook-tick', opts: { removeOnComplete: true, removeOnFail: 100 } });
const hooksWorker = new Worker(
  HOOKS_QUEUE,
  async () => {
    const r = await webhookTick(handle.db, config, secretBox);
    if (r.attempted) log.info(r, 'webhook deliveries');
  },
  { connection, concurrency: 1, lockDuration: 120_000 },
);
hooksWorker.on('failed', (job, err) => log.error({ job: job?.name, err }, 'webhook job failed'));
log.info('worker started');

const shutdown = async () => {
  await Promise.all([worker.close(), feedsWorker.close(), hooksWorker.close()]);
  await Promise.all([queue.close(), feedsQueue.close(), hooksQueue.close()]);
  await handle.close();
  process.exit(0);
};
process.on('SIGTERM', () => void shutdown());
process.on('SIGINT', () => void shutdown());
