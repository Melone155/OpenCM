/**
 * Tamper detection. Everything that is executed on a device carries a SHA-256 hash that was
 * computed when it was saved (script version, uploaded installer, generated package step).
 * Before anything leaves the server the content is re-hashed and compared 1:1 with that hash
 * (and with the original source record); the agent repeats the check after verifying the
 * Ed25519 signature. Any mismatch aborts with an error starting with "integrity:" and an
 * audit entry "security.integrity_violation".
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { and, eq, inArray, isNull } from 'drizzle-orm';
import { SYSTEM_ACTOR, writeAudit } from './audit.ts';
import type { Db } from './db/client.ts';
import { packageVersions, scriptVersions, type RunStep } from './db/schema.ts';
import { HttpError } from './http.ts';
import { emitEvent } from './webhooks/events.ts';

export const INTEGRITY_PREFIX = 'integrity:';

// ---------------------------------------------------------------- seals
//
// A hash stored next to the content only helps against changing the content alone. Whoever can
// write to the database could change content AND hash. Therefore every hash is additionally sealed
// with an HMAC whose key lives only in PKI_DIR/integrity.key (file system, never in the DB).

let sealKey: Buffer | null = null;

/** Loads (or on first start creates) PKI_DIR/integrity.key. Server, agent endpoint and worker need it. */
export async function initIntegrityKey(dir: string): Promise<void> {
  const keyPath = join(dir, 'integrity.key');
  try {
    const key = Buffer.from((await readFile(keyPath, 'utf8')).trim(), 'base64');
    if (key.length !== 32) throw new Error('invalid key length');
    sealKey = key;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error(`integrity.key is unreadable: ${(err as Error).message}`);
    const key = randomBytes(32);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const tmp = `${keyPath}.tmp`;
    await writeFile(tmp, key.toString('base64'), { mode: 0o600 });
    await chmod(tmp, 0o600).catch(() => {});
    await rename(tmp, keyPath);
    sealKey = key;
  }
}

function hmac(message: string): string {
  if (!sealKey) throw new Error('integrity key not initialised (initIntegrityKey)');
  return createHmac('sha256', sealKey).update(message).digest('hex');
}

function sameHex(a: string | null | undefined, b: string): boolean {
  if (!a || a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

export const scriptVersionSeal = (versionId: string, sha256: string) => hmac(`opencm-script:v1:${versionId}:${sha256}`);
const stepMessage = (s: Pick<RunStep, 'sha256' | 'files'>) => `opencm-step:v1:${s.sha256}:${(s.files ?? []).map((f) => f.sha256).join(',')}`;

/** Seals a step that was generated in-process (package / patch steps). */
export function sealStep<T extends RunStep>(s: T): T {
  return { ...s, seal: hmac(stepMessage(s)) };
}
export const stepSealValid = (s: RunStep) => sameHex(s.seal, hmac(stepMessage(s)));

/** Seals script versions saved before seals existed (run once at server start). */
export async function sealUnsealedScriptVersions(db: Db): Promise<number> {
  const rows = await db.select({ id: scriptVersions.id, sha256: scriptVersions.sha256, content: scriptVersions.content }).from(scriptVersions).where(isNull(scriptVersions.seal));
  let n = 0;
  for (const r of rows) {
    if (sha256hex(r.content) !== r.sha256) continue; // never legitimise an already inconsistent row
    await db.update(scriptVersions).set({ seal: scriptVersionSeal(r.id, r.sha256) }).where(and(eq(scriptVersions.id, r.id), isNull(scriptVersions.seal)));
    n++;
  }
  return n;
}

export class IntegrityError extends HttpError {
  constructor(message: string) {
    super(409, 'integrity_violation', `${INTEGRITY_PREFIX} ${message}`);
  }
}

export const sha256hex = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');

/** Error texts that mean "refused because of a hash/signature mismatch" (server or agent). */
export function isIntegrityMessage(m: string | null | undefined): boolean {
  return !!m && /integrity:|hash mismatch|task verification failed|signature does not match/i.test(m);
}

export function withIntegrityPrefix(m: string): string {
  return m.startsWith(INTEGRITY_PREFIX) ? m : `${INTEGRITY_PREFIX} ${m}`;
}

/** Content of every step must hash to the stored sha256 (no DB access). */
export function assertStepHashes(steps: RunStep[]): void {
  for (const s of steps) {
    if (!/^[0-9a-f]{64}$/.test(s.sha256) || sha256hex(s.content) !== s.sha256) {
      throw new IntegrityError(`Schritt ${s.position} („${s.scriptName}“): Inhalt passt nicht zum gespeicherten SHA-256-Hash`);
    }
  }
}

/**
 * Full check before dispatch: step content vs. step hash, and step hash vs. the record the
 * step was created from (approved script version / package version file). Returns a
 * message on mismatch, null if everything is identical.
 */
export async function verifySteps(db: Db, steps: RunStep[]): Promise<string | null> {
  try {
    assertStepHashes(steps);
  } catch (e) {
    return (e as Error).message;
  }
  const scriptIds = [...new Set(steps.map((s) => s.scriptVersionId).filter(Boolean))];
  if (scriptIds.length) {
    const rows = await db
      .select({ id: scriptVersions.id, sha256: scriptVersions.sha256, content: scriptVersions.content, seal: scriptVersions.seal })
      .from(scriptVersions)
      .where(inArray(scriptVersions.id, scriptIds));
    for (const s of steps.filter((x) => x.scriptVersionId)) {
      const v = rows.find((r) => r.id === s.scriptVersionId);
      if (!v) return `${INTEGRITY_PREFIX} Schritt ${s.position}: Skriptversion existiert nicht mehr`;
      if (sha256hex(v.content) !== v.sha256) return `${INTEGRITY_PREFIX} Skriptversion „${s.scriptName}“ v${s.version} wurde in der Datenbank verändert (Hash stimmt nicht)`;
      if (!sameHex(v.seal, scriptVersionSeal(v.id, v.sha256))) return `${INTEGRITY_PREFIX} Skriptversion „${s.scriptName}“ v${s.version}: Hash-Siegel ungültig – Inhalt und Hash wurden gemeinsam verändert`;
      if (v.sha256 !== s.sha256) return `${INTEGRITY_PREFIX} Schritt ${s.position} („${s.scriptName}“) weicht von der freigegebenen Skriptversion ab`;
      if (s.seal && !stepSealValid(s)) return `${INTEGRITY_PREFIX} Schritt ${s.position} („${s.scriptName}“): Hash-Siegel ungültig`;
    }
  }
  for (const s of steps.filter((x) => !x.scriptVersionId)) {
    // generated steps (packages, patches) are sealed when they are created
    if (!stepSealValid(s)) return `${INTEGRITY_PREFIX} Schritt ${s.position} („${s.scriptName}“): Hash-Siegel fehlt oder ist ungültig – Inhalt oder Hash wurden verändert`;
  }
  const pkgIds = [...new Set(steps.map((s) => s.packageVersionId).filter((x): x is string => !!x))];
  if (pkgIds.length) {
    const rows = await db.select({ id: packageVersions.id, fileSha256: packageVersions.fileSha256 }).from(packageVersions).where(inArray(packageVersions.id, pkgIds));
    for (const s of steps.filter((x) => x.packageVersionId)) {
      const v = rows.find((r) => r.id === s.packageVersionId);
      if (!v) return `${INTEGRITY_PREFIX} Schritt ${s.position}: Paketversion existiert nicht mehr`;
      for (const f of s.files ?? []) {
        if (f.sha256 !== v.fileSha256) return `${INTEGRITY_PREFIX} Schritt ${s.position}: Installationsdatei „${f.name}“ weicht von der freigegebenen Paketversion ab`;
      }
    }
  }
  return null;
}

/**
 * Called when a run is created: verifies every step against its source and returns the steps
 * sealed for later checks (dispatch). Throws IntegrityError (409) on any mismatch.
 */
export async function prepareSteps(db: Db, steps: RunStep[]): Promise<RunStep[]> {
  const violation = await verifySteps(db, steps);
  if (violation) {
    await reportIntegrityViolation(db, { message: violation, source: 'server' });
    throw new IntegrityError(violation.slice(INTEGRITY_PREFIX.length).trim());
  }
  return steps.map((s) => (s.seal ? s : sealStep(s)));
}

export async function reportIntegrityViolation(
  db: Db,
  info: { message: string; deviceId?: string | null; taskId?: string | null; runId?: string | null; source: 'server' | 'agent' | 'repository' },
): Promise<void> {
  await writeAudit(db, { ...SYSTEM_ACTOR, name: 'integrity-check' }, {
    action: 'security.integrity_violation',
    targetType: info.taskId ? 'task' : info.runId ? 'run' : 'package_file',
    targetId: info.taskId ?? info.runId ?? undefined,
    details: { message: info.message, deviceId: info.deviceId ?? null, runId: info.runId ?? null, detectedBy: info.source },
  });
  await emitEvent(db, 'security.integrity_violation', { message: info.message, deviceId: info.deviceId ?? null, taskId: info.taskId ?? null, runId: info.runId ?? null, detectedBy: info.source });
}
