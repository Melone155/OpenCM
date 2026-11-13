import { createHmac } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { and, asc, eq, lte } from 'drizzle-orm';
import type { SecretBox } from '../auth/secretbox.ts';
import type { Config } from '../config.ts';
import type { Db } from '../db/client.ts';
import { webhookDeliveries, webhooks } from '../db/schema.ts';
import { HttpError } from '../http.ts';

/** Delay before attempt n+1 (after n failed attempts); after the last one the delivery fails. */
export const BACKOFF_MS = [60_000, 5 * 60_000, 30 * 60_000, 2 * 3600_000, 6 * 3600_000];
export const MAX_ATTEMPTS = BACKOFF_MS.length + 1;
const LEASE_MS = 2 * 60_000;

export interface DeliverDeps {
  fetch: (url: string, init: { method: string; headers: Record<string, string>; body: string; signal: AbortSignal }) => Promise<{ status: number; ok: boolean }>;
  /** resolves a host name to its addresses (DNS) */
  resolve: (host: string) => Promise<string[]>;
  now: () => Date;
}

export const defaultDeliverDeps: DeliverDeps = {
  fetch: (url, init) => fetch(url, { ...init, redirect: 'manual' }),
  resolve: async (host) => (await lookup(host, { all: true })).map((a) => a.address),
  now: () => new Date(),
};

/** Link-local and cloud metadata endpoints are never valid targets. */
export function blockedAddress(ip: string): boolean {
  const v = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (/^169\.254\./.test(v) || v.startsWith('::ffff:169.254.')) return true;
  if (/^fe[89ab][0-9a-f]:/.test(v)) return true; // fe80::/10
  if (v === 'fd00:ec2::254') return true;
  if (v === '0.0.0.0' || v === '::') return true;
  return false;
}

/** Static URL validation (on save). */
export function validateWebhookUrl(raw: string, allowHttp: boolean): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new HttpError(400, 'validation_error', 'Invalid URL');
  }
  if (u.protocol !== 'https:' && !(allowHttp && u.protocol === 'http:')) {
    throw new HttpError(400, 'validation_error', allowHttp ? 'Only http(s) URLs are allowed' : 'Only https:// URLs are allowed (WEBHOOK_ALLOW_HTTP=true permits http)');
  }
  if (u.username || u.password) throw new HttpError(400, 'validation_error', 'Credentials in the URL are not allowed – use the signature secret');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (host === 'metadata.google.internal' || (isIP(host) && blockedAddress(host))) throw new HttpError(400, 'validation_error', 'Link-local / metadata addresses are not allowed');
  return u;
}

export function sign(secret: string, timestamp: string, body: string): string {
  return `sha256=${createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex')}`;
}

type DeliveryRow = typeof webhookDeliveries.$inferSelect;
type HookRow = typeof webhooks.$inferSelect;

/** One HTTP attempt. Returns the result; does not touch the database. */
async function attempt(config: Config, secretBox: SecretBox, deps: DeliverDeps, hook: HookRow, d: DeliveryRow) {
  const url = validateWebhookUrl(hook.url, config.WEBHOOK_ALLOW_HTTP);
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const addrs = isIP(host) ? [host] : await deps.resolve(host);
  if (addrs.some(blockedAddress)) throw new Error('target resolves to a link-local / metadata address');
  const body = JSON.stringify({ id: d.id, ...d.payload });
  const timestamp = String(Math.floor(deps.now().getTime() / 1000));
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), config.WEBHOOK_TIMEOUT_MS);
  try {
    const res = await deps.fetch(url.toString(), {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'user-agent': 'OpenCM-Webhook',
        'x-opencm-event': d.event,
        'x-opencm-delivery': d.id,
        'x-opencm-timestamp': timestamp,
        'x-opencm-signature': sign(secretBox.open(hook.secretEnc), timestamp, body),
      },
      body,
      signal: ac.signal,
    });
    return { status: res.status, ok: res.status >= 200 && res.status < 300 };
  } finally {
    clearTimeout(timer);
  }
}

/** Delivers one (already claimed) delivery and records the outcome. */
export async function deliverOne(db: Db, config: Config, secretBox: SecretBox, deps: DeliverDeps, d: DeliveryRow, hook: HookRow) {
  const now = deps.now();
  let status: number | null = null;
  let error: string | null = null;
  try {
    const r = await attempt(config, secretBox, deps, hook, d);
    status = r.status;
    if (!r.ok) error = `HTTP ${r.status}`;
  } catch (e) {
    error = (e as Error).name === 'AbortError' ? `timeout after ${config.WEBHOOK_TIMEOUT_MS} ms` : (e as Error).message.slice(0, 500);
  }
  const attempts = d.attempts; // already incremented by the claim
  const set =
    error === null
      ? { status: 'succeeded', responseStatus: status, lastError: null, deliveredAt: now }
      : attempts >= MAX_ATTEMPTS
        ? { status: 'failed', responseStatus: status, lastError: error }
        : { status: 'pending', responseStatus: status, lastError: error, nextAttemptAt: new Date(now.getTime() + BACKOFF_MS[attempts - 1]!) };
  const [row] = await db.update(webhookDeliveries).set(set).where(eq(webhookDeliveries.id, d.id)).returning();
  return row!;
}

/** Claims a pending delivery (lease) so concurrent workers do not send it twice. */
export async function claimDelivery(db: Db, d: DeliveryRow, now: Date) {
  const [c] = await db
    .update(webhookDeliveries)
    .set({ attempts: d.attempts + 1, nextAttemptAt: new Date(now.getTime() + LEASE_MS) })
    .where(and(eq(webhookDeliveries.id, d.id), eq(webhookDeliveries.status, 'pending'), eq(webhookDeliveries.attempts, d.attempts)))
    .returning();
  return c ?? null;
}

export async function webhookTick(db: Db, config: Config, secretBox: SecretBox, deps: DeliverDeps = defaultDeliverDeps, limit = 50) {
  const now = deps.now();
  const due = await db
    .select({ d: webhookDeliveries, h: webhooks })
    .from(webhookDeliveries)
    .innerJoin(webhooks, eq(webhooks.id, webhookDeliveries.webhookId))
    .where(and(eq(webhookDeliveries.status, 'pending'), lte(webhookDeliveries.nextAttemptAt, now), eq(webhooks.enabled, true)))
    .orderBy(asc(webhookDeliveries.nextAttemptAt))
    .limit(limit);
  let succeeded = 0;
  let failed = 0;
  for (const { d, h } of due) {
    const claimed = await claimDelivery(db, d, now);
    if (!claimed) continue;
    const r = await deliverOne(db, config, secretBox, deps, claimed, h);
    if (r.status === 'succeeded') succeeded++;
    else failed++;
  }
  return { attempted: succeeded + failed, succeeded, failed };
}
