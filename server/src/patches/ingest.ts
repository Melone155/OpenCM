import { and, asc, eq, notInArray, sql } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { devicePatches, devicePatchState, taskOutput, type RunStep, type StepResult } from '../db/schema.ts';
import { emitEvent } from '../webhooks/events.ts';
import { PATCH_BEGIN, PATCH_END } from './scripts.ts';

export interface ParsedUpdate {
  updateId: string;
  title: string;
  kb: string | null;
  classification: string;
  severity: string;
  security: boolean;
  version: string;
  rebootRequired: boolean;
}

export interface ParsedScan {
  source: string;
  rebootPending: boolean;
  updates: ParsedUpdate[];
}

const SOURCES = new Set(['windows_update', 'apt', 'dnf', 'softwareupdate']);
const MAX_UPDATES = 5000;

/** Parses the last marker block of a scan output; null if there is none (or it is malformed). */
export function parsePatchOutput(text: string): ParsedScan | null {
  const end = text.lastIndexOf(PATCH_END);
  if (end < 0) return null;
  const begin = text.lastIndexOf(PATCH_BEGIN, end);
  if (begin < 0) return null;
  const lines = text.slice(begin + PATCH_BEGIN.length, end).split(/\r?\n/);
  let source = '';
  let rebootPending = false;
  const updates = new Map<string, ParsedUpdate>();
  for (const raw of lines) {
    const line = raw.replace(/\r$/, '');
    if (!line.trim()) continue;
    const f = line.split('\t');
    if (f[0] === 'S') source = (f[1] ?? '').trim();
    else if (f[0] === 'R') rebootPending = (f[1] ?? '').trim() === '1';
    else if (f[0] === 'U' && f[1]?.trim() && updates.size < MAX_UPDATES) {
      const id = f[1].trim().slice(0, 300);
      updates.set(id, {
        updateId: id,
        title: (f[2] ?? '').trim().slice(0, 500) || id,
        kb: (f[3] ?? '').trim().slice(0, 200) || null,
        classification: (f[4] ?? '').trim().slice(0, 100),
        severity: (f[5] ?? '').trim().slice(0, 50),
        security: (f[6] ?? '').trim() === '1',
        version: (f[7] ?? '').trim().slice(0, 100),
        rebootRequired: (f[8] ?? '').trim() === '1',
      });
    }
  }
  if (!SOURCES.has(source)) return null;
  return { source, rebootPending, updates: [...updates.values()] };
}

/** Replaces the device's pending updates with a scan result. */
export async function storeScan(db: Db, deviceId: string, scan: ParsedScan, now = new Date()): Promise<void> {
  await db.transaction(async (tx) => {
    const keep = scan.updates.map((u) => u.updateId);
    await tx
      .delete(devicePatches)
      .where(keep.length ? and(eq(devicePatches.deviceId, deviceId), notInArray(devicePatches.updateId, keep)) : eq(devicePatches.deviceId, deviceId));
    // other sources (e.g. after an OS change) are stale as well
    await tx.delete(devicePatches).where(and(eq(devicePatches.deviceId, deviceId), notInArray(devicePatches.source, [scan.source])));
    for (let i = 0; i < scan.updates.length; i += 500) {
      const chunk = scan.updates.slice(i, i + 500).map((u) => ({ deviceId, source: scan.source, ...u, detectedAt: now }));
      await tx
        .insert(devicePatches)
        .values(chunk)
        .onConflictDoUpdate({
          target: [devicePatches.deviceId, devicePatches.source, devicePatches.updateId],
          set: {
            // detected_at keeps the first detection date; everything else is refreshed
            title: sqlExcluded('title'),
            kb: sqlExcluded('kb'),
            classification: sqlExcluded('classification'),
            severity: sqlExcluded('severity'),
            security: sqlExcluded('security'),
            version: sqlExcluded('version'),
            rebootRequired: sqlExcluded('reboot_required'),
          },
        });
    }
    await tx
      .insert(devicePatchState)
      .values({ deviceId, source: scan.source, lastScanAt: now, lastScanStatus: 'ok', lastError: null, rebootPending: scan.rebootPending })
      .onConflictDoUpdate({
        target: devicePatchState.deviceId,
        set: { source: scan.source, lastScanAt: now, lastScanStatus: 'ok', lastError: null, rebootPending: scan.rebootPending },
      });
  });
}

export async function storeScanFailure(db: Db, deviceId: string, error: string, now = new Date()): Promise<void> {
  await db
    .insert(devicePatchState)
    .values({ deviceId, lastScanAt: now, lastScanStatus: 'failed', lastError: error.slice(0, 1000) })
    .onConflictDoUpdate({ target: devicePatchState.deviceId, set: { lastScanAt: now, lastScanStatus: 'failed', lastError: error.slice(0, 1000) } });
  await emitEvent(db, 'patch.scan_failed', { deviceId, error: error.slice(0, 1000) }, now);
}

/**
 * Called by the task engine once a task is final. If the run contained a patch scan,
 * its stdout is parsed and stored.
 */
export async function afterTaskFinished(db: Db, deviceId: string, taskId: string, steps: RunStep[], results: StepResult[], error: string | null): Promise<void> {
  const scan = steps.find((s) => s.kind === 'patch_scan');
  if (!scan) return;
  const sr = results.find((r) => r.position === scan.position);
  if (!sr || sr.status !== 'succeeded') {
    await storeScanFailure(db, deviceId, error ?? `Patch-Scan ${sr ? sr.status : 'nicht ausgeführt'}${sr?.exitCode != null ? ` (Exitcode ${sr.exitCode})` : ''}`);
    return;
  }
  const rows = await db
    .select({ data: taskOutput.data })
    .from(taskOutput)
    .where(and(eq(taskOutput.taskId, taskId), eq(taskOutput.stream, 'stdout')))
    .orderBy(asc(taskOutput.id));
  const parsed = parsePatchOutput(rows.map((r) => r.data).join(''));
  if (!parsed) {
    await storeScanFailure(db, deviceId, 'Scan-Ausgabe fehlt oder ist unvollständig (Ausgabe gekürzt?)');
    return;
  }
  await storeScan(db, deviceId, parsed);
}

function sqlExcluded(column: string) {
  return sql.raw(`excluded."${column}"`);
}
