/**
 * Fleet key figures. computeMetrics() is used live by GET /dashboard (restricted to the
 * caller's device scope) and hourly by the worker, which stores the day's global values
 * in metrics_daily for trend charts.
 */
import { and, count, countDistinct, eq, gte, inArray, isNull, lt, or, sql, type SQL } from 'drizzle-orm';
import type { DeviceScope } from './auth/scope.ts';
import { onlineThresholdSeconds, type Config } from './config.ts';
import type { Db } from './db/client.ts';
import { assets, auditLog, deployments, devicePatches, devicePatchState, devices, deviceVulnerabilities, metricsDaily, tasks, vulnerabilities } from './db/schema.ts';
import { evaluateLicenses, listLicenses } from './licenses.ts';
import { securityMetrics } from './security/posture.ts';

export const METRIC_KEYS = [
  'devices.total',
  'devices.online',
  'devices.stale7d',
  'vuln.findings_open',
  'vuln.devices_critical',
  'vuln.devices_kev',
  'patches.devices_security',
  'patches.missing_total',
  'patches.reboot_pending',
  'tasks.failed_24h',
  'integrity.violations_7d',
  'licenses.overused',
  'security.noncompliant',
  'security.unencrypted',
] as const;
export type MetricKey = (typeof METRIC_KEYS)[number];

const scopeCond = (scope: DeviceScope | null): SQL | undefined => (!scope || scope.all ? undefined : scope.ids.size ? inArray(devices.id, [...scope.ids]) : sql`false`);
const n = (rows: { n: number }[]) => Number(rows[0]?.n ?? 0);

export async function deviceMetrics(db: Db, config: Config, scope: DeviceScope | null, now = new Date()) {
  const active = and(eq(devices.status, 'active'), scopeCond(scope));
  const onlineSince = new Date(now.getTime() - onlineThresholdSeconds(config) * 1000);
  const staleSince = new Date(now.getTime() - 7 * 86_400_000);
  const [total, online, stale, byOs] = await Promise.all([
    db.select({ n: count() }).from(devices).where(active),
    db.select({ n: count() }).from(devices).where(and(active, gte(devices.lastSeenAt, onlineSince))),
    db.select({ n: count() }).from(devices).where(and(active, or(isNull(devices.lastSeenAt), lt(devices.lastSeenAt, staleSince)))),
    db.select({ os: devices.os, n: count() }).from(devices).where(active).groupBy(devices.os),
  ]);
  return { total: n(total), online: n(online), stale7d: n(stale), byOs: Object.fromEntries(byOs.map((r) => [r.os, Number(r.n)])) };
}

export async function vulnMetrics(db: Db, scope: DeviceScope | null) {
  const base = and(eq(devices.status, 'active'), eq(deviceVulnerabilities.status, 'open'), isNull(vulnerabilities.acceptedAt), scopeCond(scope));
  const q = () =>
    db
      .select({ n: countDistinct(deviceVulnerabilities.deviceId) })
      .from(deviceVulnerabilities)
      .innerJoin(devices, eq(devices.id, deviceVulnerabilities.deviceId))
      .innerJoin(vulnerabilities, eq(vulnerabilities.cveId, deviceVulnerabilities.cveId));
  const [findings, critical, kev] = await Promise.all([
    db
      .select({ n: count() })
      .from(deviceVulnerabilities)
      .innerJoin(devices, eq(devices.id, deviceVulnerabilities.deviceId))
      .innerJoin(vulnerabilities, eq(vulnerabilities.cveId, deviceVulnerabilities.cveId))
      .where(base),
    q().where(and(base, eq(vulnerabilities.cvssSeverity, 'CRITICAL'))),
    q().where(and(base, eq(vulnerabilities.kev, true))),
  ]);
  return { findingsOpen: n(findings), devicesCritical: n(critical), devicesKev: n(kev) };
}

export async function patchMetrics(db: Db, scope: DeviceScope | null) {
  const active = and(eq(devices.status, 'active'), scopeCond(scope));
  const [sec, total, reboot] = await Promise.all([
    db.select({ n: countDistinct(devicePatches.deviceId) }).from(devicePatches).innerJoin(devices, eq(devices.id, devicePatches.deviceId)).where(and(active, eq(devicePatches.security, true))),
    db.select({ n: count() }).from(devicePatches).innerJoin(devices, eq(devices.id, devicePatches.deviceId)).where(active),
    db.select({ n: count() }).from(devicePatchState).innerJoin(devices, eq(devices.id, devicePatchState.deviceId)).where(and(active, eq(devicePatchState.rebootPending, true))),
  ]);
  return { devicesSecurity: n(sec), missingTotal: n(total), rebootPending: n(reboot) };
}

export async function taskMetrics(db: Db, scope: DeviceScope | null, now = new Date()) {
  const since = new Date(now.getTime() - 86_400_000);
  const [failed] = await db
    .select({ n: count() })
    .from(tasks)
    .innerJoin(devices, eq(devices.id, tasks.deviceId))
    .where(and(inArray(tasks.status, ['failed', 'timeout']), gte(tasks.finishedAt, since), scopeCond(scope)));
  return { failed24h: Number(failed?.n ?? 0) };
}

export async function integrityMetrics(db: Db, now = new Date()) {
  const [r] = await db
    .select({ n: count() })
    .from(auditLog)
    .where(and(eq(auditLog.action, 'security.integrity_violation'), gte(auditLog.at, new Date(now.getTime() - 7 * 86_400_000))));
  return { violations7d: Number(r?.n ?? 0) };
}

export async function deploymentMetrics(db: Db) {
  const rows = await db.select({ status: deployments.status, n: count() }).from(deployments).where(inArray(deployments.status, ['running', 'paused'])).groupBy(deployments.status);
  const by = Object.fromEntries(rows.map((r) => [r.status, Number(r.n)]));
  return { running: by.running ?? 0, paused: by.paused ?? 0 };
}

export async function licenseMetrics(db: Db) {
  const list = await listLicenses(db);
  return { total: list.length, overused: list.filter((l) => l.overused).length, expiringSoon: list.filter((l) => l.expiringSoon).length, expired: list.filter((l) => l.expired).length };
}

export async function assetMetrics(db: Db) {
  const [r] = await db
    .select({
      total: sql<number>`count(*) filter (where ${assets.status} <> 'retired')::int`,
      inStock: sql<number>`count(*) filter (where ${assets.status} = 'in_stock')::int`,
      warrantyExpiring30d: sql<number>`count(*) filter (where ${assets.status} <> 'retired' and ${assets.warrantyUntil} between current_date and current_date + 30)::int`,
      warrantyExpired: sql<number>`count(*) filter (where ${assets.status} <> 'retired' and ${assets.warrantyUntil} < current_date)::int`,
    })
    .from(assets);
  return { total: Number(r?.total ?? 0), inStock: Number(r?.inStock ?? 0), warrantyExpiring30d: Number(r?.warrantyExpiring30d ?? 0), warrantyExpired: Number(r?.warrantyExpired ?? 0) };
}

/** Global values for all metric keys (worker). */
export async function computeAllMetrics(db: Db, config: Config, now = new Date()): Promise<Record<MetricKey, number>> {
  const [d, v, p, t, i, l, s] = await Promise.all([
    deviceMetrics(db, config, null, now),
    vulnMetrics(db, null),
    patchMetrics(db, null),
    taskMetrics(db, null, now),
    integrityMetrics(db, now),
    licenseMetrics(db),
    securityMetrics(db, null),
  ]);
  return {
    'devices.total': d.total,
    'devices.online': d.online,
    'devices.stale7d': d.stale7d,
    'vuln.findings_open': v.findingsOpen,
    'vuln.devices_critical': v.devicesCritical,
    'vuln.devices_kev': v.devicesKev,
    'patches.devices_security': p.devicesSecurity,
    'patches.missing_total': p.missingTotal,
    'patches.reboot_pending': p.rebootPending,
    'tasks.failed_24h': t.failed24h,
    'integrity.violations_7d': i.violations7d,
    'licenses.overused': l.overused,
    'security.noncompliant': s.noncompliant,
    'security.unencrypted': (s.encryption.unencrypted ?? 0) + (s.encryption.partial ?? 0),
  };
}

export const dayOf = (d: Date) => d.toISOString().slice(0, 10);

/** Hourly: upserts today's values (the last run of a day wins), prunes old days, evaluates licenses. */
export async function metricsTick(db: Db, config: Config, now = new Date()) {
  await evaluateLicenses(db);
  const values = await computeAllMetrics(db, config, now);
  const day = dayOf(now);
  for (const [key, value] of Object.entries(values)) {
    await db
      .insert(metricsDaily)
      .values({ day, key, value, updatedAt: now })
      .onConflictDoUpdate({ target: [metricsDaily.day, metricsDaily.key], set: { value, updatedAt: now } });
  }
  const cutoff = dayOf(new Date(now.getTime() - config.METRICS_RETENTION_DAYS * 86_400_000));
  await db.delete(metricsDaily).where(lt(metricsDaily.day, cutoff));
  return { day, values };
}

export async function metricTrends(db: Db, keys: string[], days: number, now = new Date()) {
  if (!keys.length) return {};
  const from = dayOf(new Date(now.getTime() - (days - 1) * 86_400_000));
  const rows = await db
    .select({ day: metricsDaily.day, key: metricsDaily.key, value: metricsDaily.value })
    .from(metricsDaily)
    .where(and(inArray(metricsDaily.key, keys), gte(metricsDaily.day, from)))
    .orderBy(metricsDaily.day);
  const out: Record<string, { day: string; value: number }[]> = {};
  for (const k of keys) out[k] = [];
  for (const r of rows) out[r.key]!.push({ day: r.day, value: r.value });
  return out;
}
