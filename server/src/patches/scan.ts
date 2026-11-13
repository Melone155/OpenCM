import { and, eq, gt, inArray, isNull, lt, or } from 'drizzle-orm';
import { onlineThresholdSeconds, type Config } from '../config.ts';
import type { Db } from '../db/client.ts';
import { devicePatchState, devices } from '../db/schema.ts';
import { sealStep } from '../integrity.ts';
import { createRun, DEFAULT_OPTIONS } from '../jobs/engine.ts';
import { patchScanStep, PATCH_OSES, type PatchOs } from './scripts.ts';

const SCAN_TIMEOUT_SECONDS = 1800;

/** Creates one scan run per OS for the given devices and marks them as requested. */
export async function startPatchScan(db: Db, deviceIds: string[], opts: { trigger: string; triggeredBy: string | null; name: string }, now = new Date()) {
  if (!deviceIds.length) return { runIds: [] as string[], devices: 0 };
  const rows: { id: string; os: string }[] = [];
  for (let i = 0; i < deviceIds.length; i += 5000) {
    rows.push(...(await db.select({ id: devices.id, os: devices.os }).from(devices).where(and(inArray(devices.id, deviceIds.slice(i, i + 5000)), eq(devices.status, 'active')))));
  }
  const byOs = new Map<PatchOs, string[]>();
  for (const d of rows) if ((PATCH_OSES as string[]).includes(d.os)) byOs.set(d.os as PatchOs, [...(byOs.get(d.os as PatchOs) ?? []), d.id]);
  const runIds: string[] = [];
  let n = 0;
  for (const [os, ids] of byOs) {
    const run = await createRun(db, {
      jobId: null,
      name: byOs.size > 1 ? `${opts.name} (${os})` : opts.name,
      trigger: opts.trigger,
      triggeredBy: opts.triggeredBy,
      steps: [sealStep(patchScanStep(os))],
      options: { ...DEFAULT_OPTIONS, timeoutSeconds: SCAN_TIMEOUT_SECONDS, timezone: 'UTC' },
      deviceIds: ids,
    });
    runIds.push(run.id);
    n += ids.length;
    for (let i = 0; i < ids.length; i += 1000) {
      await db
        .insert(devicePatchState)
        .values(ids.slice(i, i + 1000).map((deviceId) => ({ deviceId, scanRequestedAt: now })))
        .onConflictDoUpdate({ target: devicePatchState.deviceId, set: { scanRequestedAt: now } });
    }
  }
  return { runIds, devices: n };
}

/** Scheduler pass: scans online devices whose last scan (request) is older than the interval. */
export async function patchScanTick(db: Db, config: Config, now = new Date(), limit = 1000) {
  if (config.PATCH_SCAN_INTERVAL_HOURS <= 0) return { runIds: [] as string[], devices: 0 };
  const cutoff = new Date(now.getTime() - config.PATCH_SCAN_INTERVAL_HOURS * 3600_000);
  const online = new Date(now.getTime() - onlineThresholdSeconds(config) * 1000);
  const due = await db
    .select({ id: devices.id })
    .from(devices)
    .leftJoin(devicePatchState, eq(devicePatchState.deviceId, devices.id))
    .where(
      and(
        eq(devices.status, 'active'),
        inArray(devices.os, PATCH_OSES),
        gt(devices.lastSeenAt, online),
        or(isNull(devicePatchState.scanRequestedAt), lt(devicePatchState.scanRequestedAt, cutoff)),
        or(isNull(devicePatchState.lastScanAt), lt(devicePatchState.lastScanAt, cutoff)),
      ),
    )
    .limit(limit);
  return startPatchScan(db, due.map((d) => d.id), { trigger: 'patch_scan', triggeredBy: null, name: 'Patch-Scan (automatisch)' }, now);
}
