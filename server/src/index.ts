import { buildAgentServer } from './agent/server.ts';
import { buildApp } from './app.ts';
import { agentTlsHostnames, loadConfig } from './config.ts';
import { connectPglite, connectPostgres } from './db/client.ts';
import { schedulerTick } from './jobs/engine.ts';
import { initPki } from './pki/ca.ts';
import { initSigner } from './pki/signing.ts';
import { ensureSeed } from './seed.ts';
import { defaultDeps, feedTick } from './vuln/feeds.ts';

const config = loadConfig();

// DATABASE_URL=pglite://<dir> runs an embedded Postgres (dev only, no Docker needed).
const url = config.DATABASE_URL;
if (!url) throw new Error('DATABASE_URL is required');
const embedded = url.startsWith('pglite://');
const handle = embedded ? await connectPglite(url.slice('pglite://'.length) || undefined) : await connectPostgres(url);

await handle.migrate();
const pki = await initPki(config.PKI_DIR, agentTlsHostnames(config));
const signer = await initSigner(config.PKI_DIR);
const app = await buildApp({ config, db: handle.db, pki, signer });
const agentApp = await buildAgentServer({ config, db: handle.db, pki, signer });
await ensureSeed(handle.db, config, app.log);

// With an embedded DB there is no separate worker process: run scheduler and feeds in-process.
let tick: NodeJS.Timeout | undefined;
let feedTimer: NodeJS.Timeout | undefined;
if (embedded) {
  tick = setInterval(() => {
    schedulerTick(handle.db, config).catch((err) => app.log.error({ err }, 'scheduler tick failed'));
  }, 15_000);
  let feedsBusy = false;
  const deps = defaultDeps((msg, data) => app.log.info(data ?? {}, msg));
  feedTimer = setInterval(() => {
    if (feedsBusy) return;
    feedsBusy = true;
    feedTick(handle.db, config, deps)
      .catch((err) => app.log.error({ err }, 'feed tick failed'))
      .finally(() => (feedsBusy = false));
  }, 60_000);
}

const shutdown = async (signal: string) => {
  app.log.info({ signal }, 'shutting down');
  clearInterval(tick);
  clearInterval(feedTimer);
  await Promise.allSettled([app.close(), agentApp.close()]);
  await handle.close();
  process.exit(0);
};
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

await app.listen({ host: config.HOST, port: config.PORT });
await agentApp.listen({ host: config.HOST, port: config.AGENT_PORT });
app.log.info({ hostnames: agentTlsHostnames(config), port: config.AGENT_PORT }, 'agent mTLS endpoint ready');
