import { createHmac } from 'node:crypto';
import { and, eq, gt, isNull, lt, or } from 'drizzle-orm';
import type { Config } from '../config.ts';
import type { Db } from '../db/client.ts';
import { devices, feedState } from '../db/schema.ts';
import { evaluateFindings, invalidateProductIndex, notableFindings, type NewFinding } from './evaluate.ts';
import { syncEpss, syncKev } from './kev-epss.ts';
import { ensureBuiltinRules } from './mapping.ts';
import { syncNvd, type FetchFn, type NvdCursor } from './nvd.ts';
import { syncOsv } from './osv.ts';
import { emitEvent } from '../webhooks/events.ts';

export const FEEDS = ['nvd', 'kev', 'epss', 'osv'] as const;
export type FeedName = (typeof FEEDS)[number];

export interface FeedDeps {
  fetch: FetchFn;
  sleep: (ms: number) => Promise<void>;
  log: (msg: string, data?: Record<string, unknown>) => void;
  now?: () => Date;
}

export const defaultDeps = (log: FeedDeps['log']): FeedDeps => ({
  fetch: (url, init) => fetch(url, { ...init, signal: AbortSignal.timeout(120_000) }),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  log,
});

const LEASE_MS = 30 * 60_000;

function intervalMs(c: Config, feed: FeedName): number {
  const hours = { nvd: c.NVD_SYNC_INTERVAL_HOURS, kev: c.KEV_SYNC_INTERVAL_HOURS, epss: c.EPSS_SYNC_INTERVAL_HOURS, osv: c.OSV_SYNC_INTERVAL_HOURS }[feed];
  return hours * 3600_000;
}

async function ensureState(db: Db, name: string) {
  await db.insert(feedState).values({ name }).onConflictDoNothing();
}

/** Atomically takes the lease of a feed (several workers may run). */
async function acquire(db: Db, name: string, now: Date): Promise<typeof feedState.$inferSelect | null> {
  await ensureState(db, name);
  const [row] = await db
    .update(feedState)
    .set({ lockedUntil: new Date(now.getTime() + LEASE_MS), lastAttemptAt: now })
    .where(and(eq(feedState.name, name), or(isNull(feedState.lockedUntil), lt(feedState.lockedUntil, now))))
    .returning();
  return row ?? null;
}

async function release(db: Db, name: string, patch: Partial<typeof feedState.$inferInsert>) {
  await db.update(feedState).set({ ...patch, lockedUntil: null }).where(eq(feedState.name, name));
}

function isDue(c: Config, feed: FeedName, s: typeof feedState.$inferSelect | undefined, now: Date): boolean {
  if (!s) return true;
  if (s.requestedAt && (!s.lastAttemptAt || s.requestedAt > s.lastAttemptAt)) return true;
  if (feed === 'nvd' && (s.cursor as NvdCursor).mode === 'full') return true; // resume mirror
  if (s.error && s.lastAttemptAt && now.getTime() - s.lastAttemptAt.getTime() < 15 * 60_000) return false; // back off after errors
  if (feed === 'osv') return true; // incremental: only unchecked/stale package versions are queried
  return !s.lastSuccessAt || now.getTime() - s.lastSuccessAt.getTime() >= intervalMs(c, feed);
}

/** Webhook for new critical / known-exploited findings (HMAC-SHA256 signed). */
export async function notifyNewFindings(db: Db, c: Config, deps: FeedDeps, findings: NewFinding[]): Promise<number> {
  if (!findings.length) return 0;
  const notable = await notableFindings(db, findings);
  if (!notable.length) return 0;
  // generic webhooks (M6): one event per batch of up to 500 findings
  for (let i = 0; i < notable.length; i += 500) await emitEvent(db, 'vulnerability.findings.new', { findings: notable.slice(i, i + 500) }, deps.now?.() ?? new Date());
  if (!c.VULN_WEBHOOK_URL) return notable.length;
  for (let i = 0; i < notable.length; i += 500) {
    const body = JSON.stringify({ event: 'vulnerability.findings.new', sentAt: (deps.now?.() ?? new Date()).toISOString(), findings: notable.slice(i, i + 500) });
    const headers: Record<string, string> = { 'content-type': 'application/json', 'user-agent': 'OpenCM' };
    if (c.VULN_WEBHOOK_SECRET) headers['x-opencm-signature'] = `sha256=${createHmac('sha256', c.VULN_WEBHOOK_SECRET).update(body).digest('hex')}`;
    try {
      const res = await deps.fetch(c.VULN_WEBHOOK_URL, { method: 'POST', headers, body });
      if (!res.ok) deps.log('webhook delivery failed', { status: res.status });
    } catch (err) {
      deps.log('webhook delivery failed', { err: (err as Error).message });
    }
  }
  return notable.length;
}

export interface FeedTickResult {
  synced: string[];
  evaluated: number;
  newFindings: number;
  notified: number;
}

/**
 * One pass: run due feed syncs (each under a lease), then re-evaluate findings —
 * everything after a sync, otherwise only devices with an inventory newer than the
 * last evaluation.
 */
export async function feedTick(db: Db, c: Config, deps: FeedDeps): Promise<FeedTickResult> {
  const now = deps.now?.() ?? new Date();
  const result: FeedTickResult = { synced: [], evaluated: 0, newFindings: 0, notified: 0 };
  await ensureBuiltinRules(db);
  const states = new Map((await db.select().from(feedState)).map((s) => [s.name, s]));

  const runFeed = async (feed: FeedName) => {
    if (!c.VULN_FEEDS_ENABLED || !isDue(c, feed, states.get(feed), now)) return;
    if (feed === 'osv' && !c.OSV_ENABLED) return;
    const lease = await acquire(db, feed, now);
    if (!lease) return;
    try {
      let stats: Record<string, unknown>;
      let cursor = lease.cursor;
      let complete = true;
      let changed = true;
      if (feed === 'osv') {
        // "sync now" re-checks every cached package version
        const st = states.get('osv');
        const force = !!st?.requestedAt && (!st.lastAttemptAt || st.requestedAt > st.lastAttemptAt);
        const r = await syncOsv(
          db,
          {
            baseUrl: c.OSV_API_URL.replace(/\/$/, ''),
            fetch: deps.fetch,
            sleep: deps.sleep,
            intervalHours: force ? 0 : c.OSV_SYNC_INTERVAL_HOURS,
            maxPackages: c.OSV_MAX_PACKAGES_PER_RUN,
            maxDetails: c.OSV_MAX_DETAILS_PER_RUN,
            log: deps.log,
          },
          now,
        );
        stats = { ...r };
        changed = r.changed;
      } else if (feed === 'kev') stats = await syncKev(db, c.KEV_URL, deps.fetch);
      else if (feed === 'epss') stats = await syncEpss(db, c.EPSS_URL, deps.fetch);
      else {
        const r = await syncNvd(db, { baseUrl: c.NVD_API_URL, apiKey: c.NVD_API_KEY, fetch: deps.fetch, sleep: deps.sleep, maxPages: c.NVD_MAX_PAGES_PER_RUN, log: deps.log }, lease.cursor as NvdCursor, now);
        cursor = r.cursor as Record<string, unknown>;
        complete = r.done;
        stats = { stored: r.stored, mode: r.cursor.mode, startIndex: r.cursor.startIndex ?? null };
        invalidateProductIndex();
      }
      // osv runs every tick: keep the last meaningful stats, report only real changes
      await release(db, feed, { cursor, error: null, ...(changed && { stats }), ...(complete && { lastSuccessAt: now }) });
      if (changed) {
        result.synced.push(feed);
        deps.log(`feed ${feed} synced`, stats);
      }
    } catch (err) {
      await release(db, feed, { error: (err as Error).message.slice(0, 500) });
      deps.log(`feed ${feed} failed`, { err: (err as Error).message });
    }
  };

  // 1) KEV (small, fast) and NVD (possibly long, resumable)
  await runFeed('kev');
  await runFeed('nvd');
  // OSV before the evaluation, so packages of new inventories are checked first
  await runFeed('osv');
  // 2) evaluation – full after feed changes, otherwise only devices with new inventory
  await evaluate(db, c, deps, now, result);
  // 3) EPSS last: it is only fetched for CVEs that have findings
  await runFeed('epss');
  return result;
}

async function evaluate(db: Db, c: Config, deps: FeedDeps, now: Date, result: FeedTickResult): Promise<void> {
  await ensureState(db, 'evaluation');
  const [evalState] = await db.select().from(feedState).where(eq(feedState.name, 'evaluation'));
  const requested = !!evalState?.requestedAt && evalState.requestedAt > (evalState.lastSuccessAt ?? new Date(0));
  const fullEval = result.synced.some((f) => f === 'nvd' || f === 'kev' || f === 'osv') || !evalState?.lastSuccessAt || requested;
  let deviceIds: string[] | undefined;
  if (!fullEval) {
    const since = evalState!.lastSuccessAt!;
    deviceIds = (await db.select({ id: devices.id }).from(devices).where(and(eq(devices.status, 'active'), gt(devices.lastInventoryAt, since)))).map((d) => d.id);
    if (!deviceIds.length) return;
  }
  const lease = await acquire(db, 'evaluation', now);
  if (!lease) return;
  try {
    const r = await evaluateFindings(db, { deviceIds, now, osv: c.OSV_ENABLED });
    result.evaluated = r.devices;
    result.newFindings = r.newFindings.length;
    result.notified = await notifyNewFindings(db, c, deps, r.newFindings);
    await release(db, 'evaluation', { lastSuccessAt: now, error: null, stats: { devices: r.devices, open: r.findingsOpen, new: r.newFindings.length, fixed: r.fixed, full: !deviceIds } });
  } catch (err) {
    await release(db, 'evaluation', { error: (err as Error).message.slice(0, 500) });
    throw err;
  }
}

/** Marks feeds as requested ("sync now"); picked up by the next feed tick. */
export async function requestSync(db: Db, feeds: string[], now = new Date()): Promise<void> {
  for (const f of [...feeds, 'evaluation']) {
    await ensureState(db, f);
    await db.update(feedState).set({ requestedAt: now }).where(eq(feedState.name, f));
  }
}
