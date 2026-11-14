import { and, asc, eq, inArray, isNotNull, lte, notInArray, or, sql } from 'drizzle-orm';
import type { Config } from '../config.ts';
import { onlineThresholdSeconds } from '../config.ts';
import type { Db } from '../db/client.ts';
import {
  customFields,
  deviceCustomValues,
  devices,
  jobRuns,
  jobs,
  jobSteps,
  scripts,
  scriptVersions,
  taskOutput,
  tasks,
  type JobOptions,
  type JobTargets,
  type RunStep,
  type StepResult,
} from '../db/schema.ts';
import { resolveTargets } from '../groups/filter.ts';
import { HttpError } from '../http.ts';
import { afterTaskFinished } from '../patches/ingest.ts';
import { emitEvent } from '../webhooks/events.ts';
import { isIntegrityMessage, prepareSteps, reportIntegrityViolation, verifySteps, withIntegrityPrefix } from '../integrity.ts';
import type { Signer, SignedEnvelope } from '../pki/signing.ts';
import { supportsOs } from './interpreters.ts';
import { inMaintenanceWindow, nextCronRun } from './schedule.ts';

export const TERMINAL = ['succeeded', 'failed', 'timeout', 'cancelled', 'skipped'] as const;
export const ACTIVE = ['dispatched', 'running'] as const;

/** Run options are the job options plus the job's time zone (for maintenance windows). */
export type RunOptions = JobOptions & { timezone: string };

export const DEFAULT_OPTIONS: JobOptions = {
  timeoutSeconds: 3600,
  maxRetries: 0,
  retryDelaySeconds: 300,
  stopOnError: true,
  maintenanceWindow: null,
};

// ---------------------------------------------------------------- runs

/** Snapshot of a job's steps. Only approved script versions may run. */
export async function snapshotJobSteps(db: Db, jobId: string): Promise<RunStep[]> {
  const rows = await db
    .select({
      position: jobSteps.position,
      params: jobSteps.params,
      continueOnError: jobSteps.continueOnError,
      customFieldId: jobSteps.customFieldId,
      scriptVersionId: scriptVersions.id,
      version: scriptVersions.version,
      status: scriptVersions.status,
      content: scriptVersions.content,
      sha256: scriptVersions.sha256,
      scriptId: scripts.id,
      scriptName: scripts.name,
      interpreter: scripts.interpreter,
    })
    .from(jobSteps)
    .innerJoin(scriptVersions, eq(scriptVersions.id, jobSteps.scriptVersionId))
    .innerJoin(scripts, eq(scripts.id, scriptVersions.scriptId))
    .where(eq(jobSteps.jobId, jobId))
    .orderBy(asc(jobSteps.position));
  if (!rows.length) throw new HttpError(409, 'job_without_steps', 'Job has no steps');
  const notApproved = rows.find((r) => r.status !== 'approved');
  if (notApproved) {
    throw new HttpError(409, 'script_not_approved', `Script "${notApproved.scriptName}" v${notApproved.version} is ${notApproved.status}, not approved`);
  }
  return rows.map(({ status: _s, ...r }) => r);
}

export interface CreateRunInput {
  jobId: string | null;
  name: string;
  trigger: string;
  triggeredBy: string | null;
  steps: RunStep[];
  options: RunOptions;
  deviceIds: string[];
  deploymentId?: string | null;
  ring?: number | null;
}

/** Creates a run with one task per device. Devices whose OS cannot run every step get `skipped`. */
export async function createRun(db: Db, input: CreateRunInput) {
  // content must still match the (sealed) hash computed when it was saved
  input = { ...input, steps: await prepareSteps(db, input.steps) };
  return db.transaction(async (tx) => {
    const [run] = await tx
      .insert(jobRuns)
      .values({
        jobId: input.jobId,
        name: input.name,
        trigger: input.trigger,
        triggeredBy: input.triggeredBy,
        steps: input.steps,
        options: input.options,
        deploymentId: input.deploymentId ?? null,
        ring: input.ring ?? null,
      })
      .returning();
    const ids = [...new Set(input.deviceIds)];
    if (ids.length) {
      const devs = await tx.select({ id: devices.id, os: devices.os }).from(devices).where(inArray(devices.id, ids));
      const now = new Date();
      await tx.insert(tasks).values(
        devs.map((d) => {
          const bad = input.steps.find((s) => !supportsOs(s.interpreter, d.os));
          return bad
            ? { runId: run!.id, deviceId: d.id, status: 'skipped', finishedAt: now, error: `Interpreter "${bad.interpreter}" is not available on ${d.os}` }
            : { runId: run!.id, deviceId: d.id };
        }),
      );
    }
    if (input.jobId) await tx.update(jobs).set({ lastRunAt: new Date() }).where(eq(jobs.id, input.jobId));
    await finalizeRunIfDone(tx as unknown as Db, run!.id);
    return run!;
  });
}

/** Starts a run for a job (all current targets, or a subset of device ids). */
export async function runJob(db: Db, config: Config, jobId: string, trigger: string, triggeredBy: string | null, onlyDeviceIds?: string[]) {
  const [job] = await db.select().from(jobs).where(eq(jobs.id, jobId));
  if (!job) throw new HttpError(404, 'not_found', 'Job not found');
  const steps = await snapshotJobSteps(db, jobId);
  let deviceIds = await resolveTargets(db, job.targets, onlineThresholdSeconds(config));
  if (onlyDeviceIds) deviceIds = deviceIds.filter((id) => onlyDeviceIds.includes(id));
  return createRun(db, {
    jobId,
    name: job.name,
    trigger,
    triggeredBy,
    steps,
    options: { ...job.options, timezone: job.timezone },
    deviceIds,
  });
}

export async function finalizeRunIfDone(db: Db, runId: string): Promise<void> {
  const [open] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(tasks)
    .where(and(eq(tasks.runId, runId), notInArray(tasks.status, [...TERMINAL])));
  if ((open?.n ?? 0) === 0) {
    const [done] = await db
      .update(jobRuns)
      .set({ status: sql`case when ${jobRuns.status} = 'cancelled' then 'cancelled' else 'completed' end`, finishedAt: new Date() })
      .where(and(eq(jobRuns.id, runId), sql`${jobRuns.finishedAt} is null`))
      .returning({ id: jobRuns.id, name: jobRuns.name, jobId: jobRuns.jobId, deploymentId: jobRuns.deploymentId, ring: jobRuns.ring, trigger: jobRuns.trigger, status: jobRuns.status });
    if (done) {
      const rows = await db.select({ status: tasks.status, n: sql<number>`count(*)::int` }).from(tasks).where(eq(tasks.runId, runId)).groupBy(tasks.status);
      await emitEvent(db, 'run.completed', { run: done, counts: Object.fromEntries(rows.map((r) => [r.status, r.n])) });
    }
  }
}

// ---------------------------------------------------------------- dispatch (agent side)

/**
 * v1: script steps only. v2: at least one step carries `files` the agent must download
 * first – agents without file support refuse v2 instead of running without the file.
 */
export interface TaskPayload {
  v: 1 | 2;
  taskId: string;
  runId: string;
  deviceId: string;
  attempt: number;
  issuedAt: string;
  expiresAt: string;
  timeoutSeconds: number;
  stopOnError: boolean;
  steps: {
    position: number;
    name: string;
    version: number;
    interpreter: string;
    content: string;
    sha256: string;
    params: Record<string, string | number | boolean>;
    continueOnError: boolean;
    captureOutput: boolean;
    files?: { sha256: string; name: string; sizeBytes: number }[];
  }[];
}

const ENVELOPE_TTL_MS = 10 * 60_000;

/** Atomically claims the next runnable task for a device and returns it signed. */
export async function claimNextTask(db: Db, signer: Signer, deviceId: string, now = new Date()): Promise<SignedEnvelope | null> {
  const candidates = await db
    .select({ task: tasks, run: { steps: jobRuns.steps, options: jobRuns.options } })
    .from(tasks)
    .innerJoin(jobRuns, eq(jobRuns.id, tasks.runId))
    .where(
      and(
        eq(tasks.deviceId, deviceId),
        eq(tasks.status, 'pending'),
        lte(tasks.notBefore, now),
        eq(tasks.cancelRequested, false),
        eq(jobRuns.status, 'running'),
      ),
    )
    .orderBy(asc(tasks.createdAt))
    .limit(20);

  const verified = new Map<string, string | null>();
  for (const c of candidates) {
    const opts = c.run.options as RunOptions;
    if (!inMaintenanceWindow(now, opts.maintenanceWindow, opts.timezone ?? 'UTC')) continue;
    const [claimed] = await db
      .update(tasks)
      .set({ status: 'dispatched', dispatchedAt: now })
      .where(and(eq(tasks.id, c.task.id), eq(tasks.status, 'pending')))
      .returning();
    if (!claimed) continue; // claimed concurrently
    const runSteps = c.run.steps as RunStep[];

    // 1:1 hash comparison with the saved sources before anything leaves the server
    if (!verified.has(claimed.runId)) verified.set(claimed.runId, await verifySteps(db, runSteps));
    const violation = verified.get(claimed.runId);
    if (violation) {
      await db.update(tasks).set({ status: 'failed', finishedAt: now, error: violation }).where(eq(tasks.id, claimed.id));
      await db.insert(taskOutput).values({ taskId: claimed.id, stream: 'system', data: `\n[ABGEBROCHEN – Hash-Prüfung fehlgeschlagen] ${violation}\n` });
      await reportIntegrityViolation(db, { message: violation, deviceId, taskId: claimed.id, runId: claimed.runId, source: 'server' });
      await finalizeRunIfDone(db, claimed.runId);
      continue;
    }
    const payload: TaskPayload = {
      v: runSteps.some((s) => s.files?.length) ? 2 : 1,
      taskId: claimed.id,
      runId: claimed.runId,
      deviceId,
      attempt: claimed.attempt,
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ENVELOPE_TTL_MS).toISOString(),
      timeoutSeconds: opts.timeoutSeconds,
      stopOnError: opts.stopOnError,
      steps: runSteps.map((s) => ({
        position: s.position,
        name: s.scriptName,
        version: s.version,
        interpreter: s.interpreter,
        content: s.content,
        sha256: s.sha256,
        params: s.params,
        continueOnError: s.continueOnError,
        captureOutput: !!s.customFieldId,
        ...(s.files?.length ? { files: s.files } : {}),
      })),
    };
    return signer.envelope(payload);
  }
  return null;
}

async function loadDeviceTask(db: Db, deviceId: string, taskId: string) {
  const [row] = await db
    .select({ task: tasks, run: jobRuns })
    .from(tasks)
    .innerJoin(jobRuns, eq(jobRuns.id, tasks.runId))
    .where(and(eq(tasks.id, taskId), eq(tasks.deviceId, deviceId)));
  if (!row) throw new HttpError(404, 'not_found', 'Task not found');
  return row;
}

export async function markStarted(db: Db, deviceId: string, taskId: string): Promise<{ cancel: boolean }> {
  const { task } = await loadDeviceTask(db, deviceId, taskId);
  if (!(ACTIVE as readonly string[]).includes(task.status)) throw new HttpError(409, 'task_not_active', `Task is ${task.status}`);
  await db.update(tasks).set({ status: 'running', startedAt: task.startedAt ?? new Date() }).where(eq(tasks.id, taskId));
  return { cancel: task.cancelRequested };
}

export async function appendOutput(
  db: Db,
  config: Config,
  deviceId: string,
  taskId: string,
  chunks: { stream: 'stdout' | 'stderr'; data: string }[],
): Promise<{ cancel: boolean }> {
  const { task } = await loadDeviceTask(db, deviceId, taskId);
  if (!(ACTIVE as readonly string[]).includes(task.status)) throw new HttpError(409, 'task_not_active', `Task is ${task.status}`);
  let budget = config.TASK_OUTPUT_MAX_BYTES - task.outputBytes;
  const rows: { taskId: string; stream: string; data: string }[] = [];
  let truncated = task.outputTruncated;
  for (const c of chunks) {
    if (!c.data) continue;
    if (budget <= 0) {
      truncated = true;
      break;
    }
    const buf = Buffer.from(c.data, 'utf8');
    const data = buf.length > budget ? buf.subarray(0, budget).toString('utf8') : c.data;
    if (buf.length > budget) truncated = true;
    budget -= Buffer.byteLength(data, 'utf8');
    rows.push({ taskId, stream: c.stream, data });
  }
  if (rows.length) await db.insert(taskOutput).values(rows);
  if (truncated && !task.outputTruncated) {
    await db.insert(taskOutput).values({ taskId, stream: 'system', data: `\n[output truncated at ${config.TASK_OUTPUT_MAX_BYTES} bytes]\n` });
  }
  await db
    .update(tasks)
    .set({
      status: 'running',
      startedAt: task.startedAt ?? new Date(),
      outputBytes: config.TASK_OUTPUT_MAX_BYTES - Math.max(budget, 0),
      outputTruncated: truncated,
    })
    .where(eq(tasks.id, taskId));
  return { cancel: task.cancelRequested };
}

export interface TaskResultInput {
  status: 'succeeded' | 'failed' | 'timeout' | 'cancelled';
  exitCode: number | null;
  error?: string | null;
  steps: (StepResult & { stdoutTail?: string })[];
}

function coerceCustomValue(type: string, raw: string): string | null {
  const v = raw.trim();
  if (!v) return null;
  switch (type) {
    case 'number':
      return /^-?\d+(\.\d+)?$/.test(v) ? v : null;
    case 'boolean': {
      const l = v.toLowerCase();
      if (['true', '1', 'yes', 'ja'].includes(l)) return 'true';
      if (['false', '0', 'no', 'nein'].includes(l)) return 'false';
      return null;
    }
    case 'date':
      return Number.isNaN(Date.parse(v)) ? null : new Date(v).toISOString();
    default:
      return v.slice(0, 1000);
  }
}

/** Final result from the agent (or a timeout from the scheduler). Applies retries and custom fields. */
export async function applyResult(db: Db, deviceId: string, taskId: string, result: TaskResultInput, now = new Date()): Promise<void> {
  const { task, run } = await loadDeviceTask(db, deviceId, taskId);
  if (!(ACTIVE as readonly string[]).includes(task.status)) throw new HttpError(409, 'task_not_active', `Task is ${task.status}`);
  const opts = run.options as RunOptions;

  // custom fields from script output
  const steps = run.steps as RunStep[];
  for (const sr of result.steps) {
    const step = steps.find((s) => s.position === sr.position);
    if (!step?.customFieldId || sr.status !== 'succeeded' || sr.stdoutTail === undefined) continue;
    const [field] = await db.select().from(customFields).where(eq(customFields.id, step.customFieldId));
    if (!field) continue;
    const lastLine = sr.stdoutTail.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).pop() ?? '';
    const value = coerceCustomValue(field.type, lastLine);
    if (value === null) {
      await db.insert(taskOutput).values({ taskId, stream: 'system', data: `\n[custom field "${field.name}": "${lastLine.slice(0, 100)}" is not a valid ${field.type}]\n` });
      continue;
    }
    await db
      .insert(deviceCustomValues)
      .values({ deviceId, fieldId: field.id, value, source: 'script', updatedAt: now })
      .onConflictDoUpdate({ target: [deviceCustomValues.deviceId, deviceCustomValues.fieldId], set: { value, source: 'script', updatedAt: now } });
  }

  const stepResults = result.steps.map(({ stdoutTail: _t, ...s }) => s);
  // the agent refused the task or a file because of a hash/signature mismatch: never retry, make it visible
  const integrity = result.status === 'failed' && isIntegrityMessage(result.error);
  if (integrity) {
    result = { ...result, error: withIntegrityPrefix(result.error!) };
    await db.insert(taskOutput).values({ taskId, stream: 'system', data: `\n[ABGEBROCHEN – Hash-Prüfung auf dem Gerät fehlgeschlagen] ${result.error}\n` });
    await reportIntegrityViolation(db, { message: result.error!, deviceId, taskId, runId: run.id, source: 'agent' });
  }
  const retry = !integrity && (result.status === 'failed' || result.status === 'timeout') && !task.cancelRequested && task.attempt <= opts.maxRetries;
  if (retry) {
    await db.insert(taskOutput).values({
      taskId,
      stream: 'system',
      data: `\n[attempt ${task.attempt} ${result.status}${result.exitCode !== null ? ` (exit code ${result.exitCode})` : ''} – retrying in ${opts.retryDelaySeconds}s]\n`,
    });
    await db
      .update(tasks)
      .set({
        status: 'pending',
        attempt: task.attempt + 1,
        notBefore: new Date(now.getTime() + opts.retryDelaySeconds * 1000),
        dispatchedAt: null,
        startedAt: null,
        exitCode: result.exitCode,
        error: result.error ?? null,
        stepResults,
      })
      .where(eq(tasks.id, taskId));
    return;
  }
  await db
    .update(tasks)
    .set({
      status: task.cancelRequested && result.status !== 'succeeded' ? 'cancelled' : result.status,
      finishedAt: now,
      exitCode: result.exitCode,
      error: result.error ?? null,
      stepResults,
    })
    .where(eq(tasks.id, taskId));
  await afterTaskFinished(db, deviceId, taskId, steps, stepResults, result.error ?? null);
  if (result.status === 'failed' || result.status === 'timeout') {
    await emitEvent(db, 'task.failed', { taskId, runId: run.id, runName: run.name, deviceId, status: result.status, exitCode: result.exitCode, error: result.error ?? null, integrity: integrity });
  }
  await finalizeRunIfDone(db, run.id);
}

// ---------------------------------------------------------------- cancel / rerun

export async function cancelTasks(db: Db, where: ReturnType<typeof eq>): Promise<number> {
  const now = new Date();
  const pending = await db
    .update(tasks)
    .set({ status: 'cancelled', finishedAt: now, error: 'cancelled by user' })
    .where(and(where, eq(tasks.status, 'pending')))
    .returning({ id: tasks.id, runId: tasks.runId });
  const active = await db
    .update(tasks)
    .set({ cancelRequested: true })
    .where(and(where, inArray(tasks.status, [...ACTIVE])))
    .returning({ id: tasks.id });
  for (const runId of new Set(pending.map((p) => p.runId))) await finalizeRunIfDone(db, runId);
  return pending.length + active.length;
}

export async function cancelRun(db: Db, runId: string): Promise<void> {
  await db.update(jobRuns).set({ status: 'cancelled' }).where(and(eq(jobRuns.id, runId), eq(jobRuns.status, 'running')));
  await cancelTasks(db, eq(tasks.runId, runId));
  await finalizeRunIfDone(db, runId);
}

/** Devices a rerun of this run would target. Throws 409 if there are none. */
export async function rerunDeviceIds(db: Db, runId: string, onlyFailed: boolean): Promise<string[]> {
  const ts = await db
    .select({ deviceId: tasks.deviceId, status: tasks.status })
    .from(tasks)
    .where(eq(tasks.runId, runId));
  const deviceIds = ts
    .filter((t) => (onlyFailed ? ['failed', 'timeout', 'cancelled'].includes(t.status) : t.status !== 'skipped'))
    .map((t) => t.deviceId);
  if (!deviceIds.length) throw new HttpError(409, 'nothing_to_rerun', 'No matching tasks to run again');
  return deviceIds;
}

export async function rerun(db: Db, runId: string, onlyFailed: boolean, triggeredBy: string | null) {
  const [run] = await db.select().from(jobRuns).where(eq(jobRuns.id, runId));
  if (!run) throw new HttpError(404, 'not_found', 'Run not found');
  const deviceIds = await rerunDeviceIds(db, runId, onlyFailed);
  return createRun(db, {
    jobId: run.jobId,
    name: run.name,
    trigger: 'rerun',
    triggeredBy,
    steps: run.steps as RunStep[],
    options: run.options as RunOptions,
    deviceIds,
  });
}

// ---------------------------------------------------------------- triggers & scheduler

/** Called from the heartbeat: agent_start / user_login jobs for this device. */
export async function fireDeviceTriggers(db: Db, config: Config, deviceId: string, events: { agentStarted: boolean; newLogins: string[] }) {
  const triggers = [...(events.agentStarted ? ['agent_start'] : []), ...(events.newLogins.length ? ['user_login'] : [])];
  if (!triggers.length) return [];
  const candidates = await db
    .select()
    .from(jobs)
    .where(and(eq(jobs.enabled, true), inArray(jobs.trigger, triggers)));
  const started: string[] = [];
  for (const job of candidates) {
    const ids = await resolveTargets(db, job.targets as JobTargets, onlineThresholdSeconds(config), deviceId);
    if (!ids.includes(deviceId)) continue;
    try {
      const run = await runJob(db, config, job.id, job.trigger, null, [deviceId]);
      started.push(run.id);
    } catch {
      // job not runnable (e.g. script retired) – ignored here, visible in the job view
    }
  }
  return started;
}

export interface TickResult {
  startedRuns: number;
  timedOut: number;
}

/** One scheduler pass. Safe to run concurrently in several workers. */
export async function schedulerTick(db: Db, config: Config, now = new Date()): Promise<TickResult> {
  let startedRuns = 0;
  // 1) due once/cron jobs: claim by advancing next_run_at atomically
  const due = await db
    .select({ id: jobs.id, trigger: jobs.trigger, cron: jobs.cron, timezone: jobs.timezone, nextRunAt: jobs.nextRunAt })
    .from(jobs)
    .where(and(eq(jobs.enabled, true), isNotNull(jobs.nextRunAt), lte(jobs.nextRunAt, now), inArray(jobs.trigger, ['once', 'cron'])));
  for (const j of due) {
    const next = j.trigger === 'cron' && j.cron ? nextCronRun(j.cron, j.timezone, now) : null;
    const [claimed] = await db
      .update(jobs)
      .set({ nextRunAt: next })
      .where(and(eq(jobs.id, j.id), eq(jobs.nextRunAt, j.nextRunAt!)))
      .returning({ id: jobs.id });
    if (!claimed) continue;
    try {
      await runJob(db, config, j.id, j.trigger, null);
      startedRuns++;
    } catch {
      // not runnable (no steps / script not approved) – skip this occurrence
    }
  }

  // 2) timeouts (agent vanished or exceeded its timeout)
  const graceMs = config.TASK_TIMEOUT_GRACE_SECONDS * 1000;
  const active = await db
    .select({ id: tasks.id, deviceId: tasks.deviceId, dispatchedAt: tasks.dispatchedAt, startedAt: tasks.startedAt, options: jobRuns.options })
    .from(tasks)
    .innerJoin(jobRuns, eq(jobRuns.id, tasks.runId))
    .where(inArray(tasks.status, [...ACTIVE]));
  let timedOut = 0;
  for (const t of active) {
    const since = (t.startedAt ?? t.dispatchedAt)?.getTime() ?? now.getTime();
    const limit = (t.options as RunOptions).timeoutSeconds * 1000 + graceMs;
    if (now.getTime() - since <= limit) continue;
    try {
      await db.insert(taskOutput).values({ taskId: t.id, stream: 'system', data: '\n[no result from agent within timeout]\n' });
      await applyResult(db, t.deviceId, t.id, { status: 'timeout', exitCode: null, error: 'timeout', steps: [] }, now);
      timedOut++;
    } catch {
      // reported concurrently
    }
  }

  // 3) runs left open (e.g. all tasks cancelled)
  const open = await db
    .select({ id: jobRuns.id })
    .from(jobRuns)
    .where(and(sql`${jobRuns.finishedAt} is null`, or(eq(jobRuns.status, 'running'), eq(jobRuns.status, 'cancelled'))));
  for (const r of open) await finalizeRunIfDone(db, r.id);

  return { startedRuns, timedOut };
}
