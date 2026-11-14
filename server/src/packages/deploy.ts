/**
 * Ring-based deployments (packages and OS updates) on top of the run/task engine.
 * Each ring becomes one run per operating system; the scheduler tick promotes to the
 * next ring once the current one is finished, its delay has passed and its success
 * quota is met – otherwise the deployment is paused for a human decision.
 */
import { and, count, eq, inArray, isNotNull, isNull, notInArray, sql } from 'drizzle-orm';
import { onlineThresholdSeconds, type Config } from '../config.ts';
import type { Db } from '../db/client.ts';
import {
  deployments,
  devices,
  jobRuns,
  packageFiles,
  packages,
  packageVersions,
  tasks,
  type DeploymentRing,
  type PatchFilter,
  type RunStep,
} from '../db/schema.ts';
import { resolveTargets } from '../groups/filter.ts';
import { conflict, HttpError, notFound } from '../http.ts';
import { cancelRun, createRun, DEFAULT_OPTIONS, TERMINAL, type RunOptions } from '../jobs/engine.ts';
import { patchInstallSteps, PATCH_OSES } from '../patches/scripts.ts';
import { INTEGRITY_PREFIX, IntegrityError, reportIntegrityViolation, sealStep } from '../integrity.ts';
import { PackageStore } from './storage.ts';
import { emitEvent } from '../webhooks/events.ts';
import { packageStep, validateAction, validatePackageVersion, type PackageAction, type PackageType, type Platform } from './generate.ts';

export type DeploymentKind = 'package' | 'os_updates';
export type DeploymentRow = typeof deployments.$inferSelect;

export interface DeploymentInput {
  name?: string;
  kind: DeploymentKind;
  packageVersionId?: string | null;
  action: PackageAction;
  patchFilter?: PatchFilter | null;
  rings: DeploymentRing[];
  options?: Partial<RunOptions>;
}

/** Loads a package version with its package and file meta. */
export async function loadPackageVersion(db: Db, versionId: string) {
  const [row] = await db
    .select({ v: packageVersions, p: packages, f: packageFiles })
    .from(packageVersions)
    .innerJoin(packages, eq(packages.id, packageVersions.packageId))
    .leftJoin(packageFiles, eq(packageFiles.sha256, packageVersions.fileSha256))
    .where(eq(packageVersions.id, versionId));
  if (!row) throw notFound('Package version');
  return row;
}

export function versionInput(v: typeof packageVersions.$inferSelect, fileSize?: number | null) {
  return {
    type: v.type as PackageType,
    fileSha256: v.fileSha256,
    fileName: v.fileName,
    fileSize: fileSize ?? null,
    packageRef: v.packageRef,
    installArgs: v.installArgs,
    installCommand: v.installCommand,
    uninstallCommand: v.uninstallCommand,
    productCode: v.productCode,
    detection: v.detection,
    successCodes: v.successCodes,
    rebootCodes: v.rebootCodes,
  };
}

/** Generated steps per OS, frozen into the deployment. */
export async function buildSteps(db: Db, input: Pick<DeploymentInput, 'kind' | 'packageVersionId' | 'action' | 'patchFilter'>) {
  if (input.kind === 'os_updates') {
    const f = input.patchFilter ?? { classification: 'security', include: [], reboot: 'never' };
    const steps: Record<string, RunStep[]> = {};
    for (const os of PATCH_OSES) steps[os] = patchInstallSteps(os, f).map(sealStep);
    return { steps, label: `Updates (${f.include.length ? `${f.include.length} ausgewählte` : f.classification})`, timeoutSeconds: 4 * 3600 };
  }
  if (!input.packageVersionId) throw new HttpError(400, 'validation_error', 'packageVersionId is required');
  const { v, p, f } = await loadPackageVersion(db, input.packageVersionId);
  if (v.status !== 'approved') throw conflict(`Package version is ${v.status}, not approved`);
  const vi = versionInput(v, f?.sizeBytes);
  const problems = [...validatePackageVersion(p.platform as Platform, vi, { requireFile: true }), ...validateAction(vi, input.action)];
  if (problems.length) throw new HttpError(409, 'package_invalid', problems.join('; '));
  // sealed now: the deployment stores the steps and later rings must run exactly this content
  const step = sealStep(packageStep({ id: p.id, name: p.name, platform: p.platform as Platform }, v.id, v.version, vi, input.action));
  return { steps: { [p.platform]: [step] }, label: `${p.name} ${v.version}`, timeoutSeconds: v.timeoutSeconds };
}

/** Devices targeted by a ring: active, OS supported by the deployment, not addressed by an earlier ring. */
export async function ringDeviceIds(db: Db, config: Config, dep: Pick<DeploymentRow, 'id' | 'rings' | 'steps'>, ring: number): Promise<Record<string, string[]>> {
  const r = dep.rings[ring];
  if (!r) return {};
  const ids = await resolveTargets(db, r.targets, onlineThresholdSeconds(config));
  const earlier = await db
    .selectDistinct({ deviceId: tasks.deviceId })
    .from(tasks)
    .innerJoin(jobRuns, eq(jobRuns.id, tasks.runId))
    .where(and(eq(jobRuns.deploymentId, dep.id), sql`${jobRuns.ring} < ${ring}`));
  const skip = new Set(earlier.map((e) => e.deviceId));
  const wanted = ids.filter((id) => !skip.has(id));
  const byOs: Record<string, string[]> = {};
  if (!wanted.length) return byOs;
  for (let i = 0; i < wanted.length; i += 5000) {
    const rows = await db
      .select({ id: devices.id, os: devices.os })
      .from(devices)
      .where(inArray(devices.id, wanted.slice(i, i + 5000)));
    for (const d of rows) if (dep.steps[d.os]) (byOs[d.os] ??= []).push(d.id);
  }
  return byOs;
}

export async function createDeployment(db: Db, input: DeploymentInput, createdBy: string | null) {
  if (!input.rings.length) throw new HttpError(400, 'validation_error', 'At least one ring is required');
  const built = await buildSteps(db, input);
  const options: RunOptions = {
    ...DEFAULT_OPTIONS,
    timeoutSeconds: built.timeoutSeconds,
    // patch runs: the trailing scan must run even if the installation failed
    stopOnError: input.kind !== 'os_updates',
    ...input.options,
    timezone: input.options?.timezone ?? 'UTC',
  };
  const verb = input.kind === 'os_updates' ? 'installieren' : input.action === 'install' ? 'installieren' : 'deinstallieren';
  const [dep] = await db
    .insert(deployments)
    .values({
      name: input.name?.trim() || `${built.label} ${verb}`,
      kind: input.kind,
      packageVersionId: input.kind === 'package' ? input.packageVersionId! : null,
      action: input.kind === 'os_updates' ? 'install' : input.action,
      patchFilter: input.kind === 'os_updates' ? (input.patchFilter ?? { classification: 'security', include: [], reboot: 'never' }) : null,
      rings: input.rings,
      steps: built.steps,
      options,
      status: 'created',
      createdBy,
    })
    .returning();
  return dep!;
}

/** Starts ring `ring` (claim must already be done by the caller). */
async function launchRing(db: Db, config: Config, dep: DeploymentRow, ring: number, triggeredBy: string | null) {
  // installer files must still be byte-identical to the upload (hash = file name)
  const store = new PackageStore(config.PACKAGE_DIR);
  for (const steps of Object.values(dep.steps)) {
    for (const f of steps.flatMap((s) => s.files ?? [])) {
      if (!(await store.verify(f.sha256))) {
        const message = `Installationsdatei „${f.name}“ fehlt oder wurde im Repository verändert (SHA-256 stimmt nicht)`;
        await reportIntegrityViolation(db, { message: `${INTEGRITY_PREFIX} ${message}`, source: 'repository' });
        throw new IntegrityError(message);
      }
    }
  }
  const byOs = await ringDeviceIds(db, config, dep, ring);
  const r = dep.rings[ring]!;
  const oses = Object.keys(byOs);
  const runIds: string[] = [];
  for (const os of oses) {
    const run = await createRun(db, {
      jobId: null,
      name: `${dep.name} – ${r.name}${oses.length > 1 ? ` (${os})` : ''}`,
      trigger: 'deployment',
      triggeredBy,
      steps: dep.steps[os]!,
      options: dep.options,
      deviceIds: byOs[os]!,
      deploymentId: dep.id,
      ring,
    });
    runIds.push(run.id);
  }
  return { runIds, devices: oses.reduce((n, os) => n + byOs[os]!.length, 0) };
}

/** Atomically moves the deployment from `from` to ring `to` and launches it. */
export async function startRing(db: Db, config: Config, id: string, from: number, to: number, triggeredBy: string | null, allowStatuses = ['created', 'running', 'paused']) {
  const [claimed] = await db
    .update(deployments)
    .set({ currentRing: to, ringStartedAt: new Date(), status: 'running', pausedReason: null, updatedAt: new Date() })
    .where(and(eq(deployments.id, id), eq(deployments.currentRing, from), inArray(deployments.status, allowStatuses)))
    .returning();
  if (!claimed) throw conflict('Deployment was changed concurrently');
  try {
    return await launchRing(db, config, claimed, to, triggeredBy);
  } catch (err) {
    const reason = `Ring „${claimed.rings[to]!.name}“ konnte nicht gestartet werden: ${(err as Error).message}`;
    await db.update(deployments).set({ status: 'paused', pausedReason: reason }).where(eq(deployments.id, id));
    await emitEvent(db, 'deployment.paused', { deploymentId: id, name: claimed.name, ring: claimed.rings[to]!.name, reason });
    throw err;
  }
}

export interface RingStats {
  ring: number;
  name: string;
  started: boolean;
  finished: boolean;
  total: number;
  succeeded: number;
  failed: number;
  pending: number;
  skipped: number;
  successPercent: number;
}

export async function ringStats(db: Db, dep: Pick<DeploymentRow, 'id' | 'rings' | 'currentRing'>): Promise<RingStats[]> {
  const rows = await db
    .select({ ring: jobRuns.ring, status: tasks.status, n: count() })
    .from(tasks)
    .innerJoin(jobRuns, eq(jobRuns.id, tasks.runId))
    .where(eq(jobRuns.deploymentId, dep.id))
    .groupBy(jobRuns.ring, tasks.status);
  return dep.rings.map((r, i) => {
    const mine = rows.filter((x) => x.ring === i);
    const by = (pred: (s: string) => boolean) => mine.filter((x) => pred(x.status)).reduce((a, b) => a + b.n, 0);
    const total = by(() => true);
    const succeeded = by((s) => s === 'succeeded');
    const skipped = by((s) => s === 'skipped');
    const pending = by((s) => !(TERMINAL as readonly string[]).includes(s));
    const failed = total - succeeded - skipped - pending;
    const relevant = total - skipped;
    return {
      ring: i,
      name: r.name,
      started: i <= dep.currentRing,
      finished: i <= dep.currentRing && pending === 0,
      total,
      succeeded,
      failed,
      pending,
      skipped,
      successPercent: relevant === 0 ? 100 : Math.floor((succeeded / relevant) * 1000) / 10,
    };
  });
}

/** One pass over running deployments; safe to run concurrently (claims). */
export async function deploymentTick(db: Db, config: Config, now = new Date()): Promise<{ promoted: number; paused: number; completed: number }> {
  const res = { promoted: 0, paused: 0, completed: 0 };

  const running = await db.select().from(deployments).where(and(eq(deployments.status, 'running'), isNotNull(deployments.ringStartedAt)));
  for (const dep of running) {
    const stats = await ringStats(db, dep);
    const cur = stats[dep.currentRing];
    if (!cur || !cur.finished) continue;
    // runs of the ring must be finalized too
    const [open] = await db
      .select({ n: count() })
      .from(jobRuns)
      .where(and(eq(jobRuns.deploymentId, dep.id), eq(jobRuns.ring, dep.currentRing), isNull(jobRuns.finishedAt)));
    if ((open?.n ?? 0) > 0) continue;

    const ring = dep.rings[dep.currentRing]!;
    if (dep.currentRing >= dep.rings.length - 1) {
      const [c] = await db
        .update(deployments)
        .set({ status: 'completed', finishedAt: now, updatedAt: now })
        .where(and(eq(deployments.id, dep.id), eq(deployments.status, 'running'), eq(deployments.currentRing, dep.currentRing)))
        .returning({ id: deployments.id });
      if (c) {
        res.completed++;
        await emitEvent(db, 'deployment.completed', { deploymentId: dep.id, name: dep.name, kind: dep.kind, rings: stats });
      }
      continue;
    }
    if (cur.successPercent < ring.minSuccessPercent) {
      const [p] = await db
        .update(deployments)
        .set({
          status: 'paused',
          pausedReason: `Erfolgsquote in Ring „${ring.name}“ ${cur.successPercent} % < ${ring.minSuccessPercent} % – manuell weiterschalten oder abbrechen`,
          updatedAt: now,
        })
        .where(and(eq(deployments.id, dep.id), eq(deployments.status, 'running'), eq(deployments.currentRing, dep.currentRing)))
        .returning({ id: deployments.id, pausedReason: deployments.pausedReason });
      if (p) {
        res.paused++;
        await emitEvent(db, 'deployment.paused', { deploymentId: dep.id, name: dep.name, ring: ring.name, successPercent: cur.successPercent, reason: p.pausedReason });
      }
      continue;
    }
    if (now.getTime() - dep.ringStartedAt!.getTime() < ring.delayHours * 3600_000) continue;
    try {
      await startRing(db, config, dep.id, dep.currentRing, dep.currentRing + 1, dep.createdBy, ['running']);
      res.promoted++;
    } catch {
      // claimed concurrently or failed to start (deployment paused with reason)
    }
  }
  return res;
}

/** Manual promotion: ignores delay and success quota, but the current ring must be finished. */
export async function promote(db: Db, config: Config, id: string, userId: string) {
  const [dep] = await db.select().from(deployments).where(eq(deployments.id, id));
  if (!dep) throw notFound('Deployment');
  if (!['running', 'paused'].includes(dep.status)) throw conflict(`Deployment is ${dep.status}`);
  const stats = await ringStats(db, dep);
  if (dep.currentRing >= 0 && !stats[dep.currentRing]?.finished) throw conflict('The current ring is still running');
  if (dep.currentRing >= dep.rings.length - 1) {
    await db.update(deployments).set({ status: 'completed', finishedAt: new Date(), pausedReason: null }).where(eq(deployments.id, id));
    return { completed: true as const };
  }
  const r = await startRing(db, config, id, dep.currentRing, dep.currentRing + 1, userId);
  return { completed: false as const, ring: dep.currentRing + 1, ...r };
}

export async function pauseDeployment(db: Db, id: string) {
  const [d] = await db
    .update(deployments)
    .set({ status: 'paused', pausedReason: 'manuell angehalten', updatedAt: new Date() })
    .where(and(eq(deployments.id, id), eq(deployments.status, 'running')))
    .returning();
  if (!d) throw conflict('Only running deployments can be paused');
  return d;
}

export async function resumeDeployment(db: Db, id: string) {
  const [d] = await db
    .update(deployments)
    .set({ status: 'running', pausedReason: null, updatedAt: new Date() })
    .where(and(eq(deployments.id, id), eq(deployments.status, 'paused'), sql`${deployments.currentRing} >= 0`))
    .returning();
  if (!d) throw conflict('Only paused deployments can be resumed');
  return d;
}

export async function cancelDeployment(db: Db, id: string) {
  const [d] = await db
    .update(deployments)
    .set({ status: 'cancelled', finishedAt: new Date(), updatedAt: new Date() })
    .where(and(eq(deployments.id, id), notInArray(deployments.status, ['completed', 'cancelled'])))
    .returning();
  if (!d) throw conflict('Deployment is already finished');
  const runs = await db
    .select({ id: jobRuns.id })
    .from(jobRuns)
    .where(and(eq(jobRuns.deploymentId, id), eq(jobRuns.status, 'running')));
  for (const r of runs) await cancelRun(db, r.id);
  return d;
}
