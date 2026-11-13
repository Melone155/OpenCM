import { and, eq, gt, isNull, lt, ne } from 'drizzle-orm';
import { getSecurity, needsApproval } from './settings.ts';
import { hasPermission, type Permission } from './auth/permissions.ts';
import { loadGrants } from './auth/rbac.ts';
import type { Config } from './config.ts';
import type { Db } from './db/client.ts';
import { approvalRequests, deployments, jobRuns, jobs, scripts, scriptVersions, tasks, users } from './db/schema.ts';
import { conflict, forbidden, HttpError, notFound } from './http.ts';
import { createRun, DEFAULT_OPTIONS, rerun, runJob } from './jobs/engine.ts';
import { nextCronRun } from './jobs/schedule.ts';
import { startRing } from './packages/deploy.ts';
import { emitEvent } from './webhooks/events.ts';

export const APPROVAL_TTL_MS = 24 * 3600_000;

export type ApprovalAction = 'job.run' | 'script.run' | 'remediation.run' | 'run.rerun' | 'job.enable' | 'deployment.start';

export interface DeploymentStartPayload {
  deploymentId: string;
  kind: 'package' | 'os_updates';
}

export interface JobRunPayload {
  jobId: string;
  jobUpdatedAt: string;
  deviceIds?: string[];
}
export interface ScriptRunPayload {
  scriptId: string;
  scriptVersionId: string;
  params: Record<string, string | number | boolean>;
  deviceIds: string[];
  timeoutSeconds: number;
}

const isPatchDeployment = (r: { action: string; payload: unknown }) =>
  r.action === 'deployment.start' && (r.payload as DeploymentStartPayload).kind === 'os_updates';

/** Permission the requester must (still) hold when the request is approved. */
function requiredPermission(r: { action: string; payload: unknown }): Permission {
  switch (r.action as ApprovalAction) {
    case 'job.enable':
      return 'jobs:update';
    case 'deployment.start':
      return isPatchDeployment(r) ? 'patches:execute' : 'software:execute';
    default:
      return 'jobs:execute';
  }
}

/** Permission a second person needs to decide the request. */
export function approverPermission(r: { action: string; payload: unknown }): Permission {
  if (r.action === 'deployment.start') return isPatchDeployment(r) ? 'patches:approve' : 'software:approve';
  return 'jobs:approve';
}

/** All permissions that allow deciding some kind of request (for listing). */
export const APPROVER_PERMISSIONS: Permission[] = ['jobs:approve', 'software:approve', 'patches:approve'];

export async function createApproval(
  db: Db,
  input: { action: ApprovalAction; summary: string; payload: object; deviceCount: number; requestedBy: string },
) {
  const [row] = await db
    .insert(approvalRequests)
    .values({ ...input, payload: input.payload as Record<string, unknown>, expiresAt: new Date(Date.now() + APPROVAL_TTL_MS) })
    .returning();
  await emitEvent(db, 'approval.requested', { approvalId: row!.id, action: row!.action, summary: row!.summary, deviceCount: row!.deviceCount, requestedBy: row!.requestedBy, expiresAt: row!.expiresAt });
  return row!;
}

/**
 * Four-eyes decision for a mass execution started by a user. Besides the size of this request,
 * the devices of the user's own recent runs count as well, so the threshold cannot be undercut
 * by splitting one mass action into several small ones (REV-008). Runs that a second person
 * approved and runs of deployments (approved as a whole) are not counted.
 */
export async function massApprovalNeeded(db: Db, config: Config, userId: string, deviceIds: string[], allDevices: boolean): Promise<boolean> {
  const security = await getSecurity(db, config);
  if (needsApproval(security, { deviceCount: deviceIds.length, allDevices })) return true;
  const threshold = security.fourEyes.deviceThreshold;
  if (!security.fourEyes.enabled || threshold <= 0 || config.FOUR_EYES_WINDOW_MINUTES <= 0 || !deviceIds.length) return false;
  const since = new Date(Date.now() - config.FOUR_EYES_WINDOW_MINUTES * 60_000);
  const approved = await db
    .select({ result: approvalRequests.result })
    .from(approvalRequests)
    .where(and(eq(approvalRequests.requestedBy, userId), eq(approvalRequests.status, 'approved'), gt(approvalRequests.decidedAt, since)));
  const approvedRuns = new Set(approved.map((a) => (a.result as { runId?: string } | null)?.runId).filter((x): x is string => !!x));
  const recent = await db
    .select({ runId: tasks.runId, deviceId: tasks.deviceId })
    .from(tasks)
    .innerJoin(jobRuns, eq(jobRuns.id, tasks.runId))
    .where(and(eq(jobRuns.triggeredBy, userId), gt(jobRuns.createdAt, since), isNull(jobRuns.deploymentId), ne(tasks.status, 'skipped')));
  const devices = new Set(deviceIds);
  for (const r of recent) if (!approvedRuns.has(r.runId)) devices.add(r.deviceId);
  return devices.size >= threshold;
}

/** Marks overdue pending requests as expired (lazy, on read). */
export async function expireApprovals(db: Db, now = new Date()): Promise<void> {
  await db
    .update(approvalRequests)
    .set({ status: 'expired', decidedAt: now })
    .where(and(eq(approvalRequests.status, 'pending'), lt(approvalRequests.expiresAt, now)));
}

async function jobUnchanged(db: Db, p: { jobId: string; jobUpdatedAt: string }) {
  const [job] = await db.select().from(jobs).where(eq(jobs.id, p.jobId));
  if (!job) throw notFound('Job');
  if (job.updatedAt.toISOString() !== p.jobUpdatedAt) throw conflict('The job was changed after the request – please request again');
  return job;
}

/** Executes an approved request on behalf of the requester. */
async function execute(db: Db, config: Config, req: typeof approvalRequests.$inferSelect): Promise<Record<string, unknown>> {
  const requester = req.requestedBy!;
  switch (req.action as ApprovalAction) {
    case 'job.run':
    case 'remediation.run': {
      const p = req.payload as unknown as JobRunPayload;
      await jobUnchanged(db, p);
      const run = await runJob(db, config, p.jobId, 'manual', requester, p.deviceIds);
      return { runId: run.id };
    }
    case 'script.run': {
      const p = req.payload as unknown as ScriptRunPayload;
      const [v] = await db
        .select({ v: scriptVersions, s: scripts })
        .from(scriptVersions)
        .innerJoin(scripts, eq(scripts.id, scriptVersions.scriptId))
        .where(eq(scriptVersions.id, p.scriptVersionId));
      if (!v) throw notFound('Script version');
      if (v.v.status !== 'approved') throw conflict(`Script version is ${v.v.status}, no longer approved`);
      const run = await createRun(db, {
        jobId: null,
        name: `Ad-hoc: ${v.s.name} v${v.v.version}`,
        trigger: 'manual',
        triggeredBy: requester,
        steps: [
          {
            position: 0,
            scriptId: v.s.id,
            scriptName: v.s.name,
            scriptVersionId: v.v.id,
            version: v.v.version,
            interpreter: v.s.interpreter,
            content: v.v.content,
            sha256: v.v.sha256,
            params: p.params,
            continueOnError: false,
            customFieldId: null,
          },
        ],
        options: { ...DEFAULT_OPTIONS, timeoutSeconds: p.timeoutSeconds, timezone: 'UTC' },
        deviceIds: p.deviceIds,
      });
      return { runId: run.id };
    }
    case 'run.rerun': {
      const p = req.payload as unknown as { runId: string; onlyFailed: boolean };
      const run = await rerun(db, p.runId, p.onlyFailed, requester);
      return { runId: run.id };
    }
    case 'job.enable': {
      const p = req.payload as unknown as JobRunPayload;
      const job = await jobUnchanged(db, p);
      const nextRunAt = job.trigger === 'cron' && job.cron ? nextCronRun(job.cron, job.timezone, new Date()) : job.trigger === 'once' ? job.runAt : null;
      // keep updatedAt: enabling is not an edit of the definition
      await db.update(jobs).set({ enabled: true, nextRunAt }).where(eq(jobs.id, job.id));
      return { jobId: job.id, enabled: true };
    }
    case 'deployment.start': {
      const p = req.payload as unknown as DeploymentStartPayload;
      const r = await startRing(db, config, p.deploymentId, -1, 0, requester, ['pending_approval']);
      return { deploymentId: p.deploymentId, runIds: r.runIds };
    }
  }
  throw new HttpError(400, 'unknown_action', `Unknown action ${req.action}`);
}

/** Four-eyes decision. The approver must be a different person; the requester must still be entitled. */
export async function decide(db: Db, config: Config, id: string, approver: { userId: string; grants: Iterable<string> }, approve: boolean, reason: string | null) {
  const approverId = approver.userId;
  await expireApprovals(db);
  const [req] = await db.select().from(approvalRequests).where(eq(approvalRequests.id, id));
  if (!req) throw notFound('Approval request');
  const needed = approverPermission(req);
  if (!hasPermission(approver.grants, needed)) throw forbidden(`Missing permission ${needed}`);
  if (req.status !== 'pending') throw conflict(`Request is ${req.status}`);
  if (req.requestedBy === approverId) throw forbidden('Four-eyes principle: you cannot approve your own request');

  // claim atomically so two approvers cannot both execute
  const [claimed] = await db
    .update(approvalRequests)
    .set({ status: approve ? 'approved' : 'rejected', decidedBy: approverId, decidedAt: new Date(), reason })
    .where(and(eq(approvalRequests.id, id), eq(approvalRequests.status, 'pending')))
    .returning();
  if (!claimed) throw conflict('Request was decided concurrently');
  if (!approve) {
    if (req.action === 'deployment.start') {
      const p = req.payload as unknown as DeploymentStartPayload;
      await db
        .update(deployments)
        .set({ status: 'cancelled', finishedAt: new Date(), pausedReason: `Freigabe abgelehnt: ${reason ?? ''}`.trim() })
        .where(and(eq(deployments.id, p.deploymentId), eq(deployments.status, 'pending_approval')));
    }
    return claimed;
  }

  try {
    const [requester] = await db.select({ isActive: users.isActive }).from(users).where(eq(users.id, req.requestedBy ?? ''));
    if (!requester?.isActive) throw forbidden('Requester no longer exists or is deactivated');
    const g = await loadGrants(db, req.requestedBy!);
    const perm = requiredPermission(req);
    if (!hasPermission(g.global, perm) && !g.scoped.some((s) => hasPermission(s.grants, perm))) throw forbidden(`Requester no longer holds ${perm}`);
    const result = await execute(db, config, req);
    const [done] = await db.update(approvalRequests).set({ result }).where(eq(approvalRequests.id, id)).returning();
    return done!;
  } catch (err) {
    const message = (err as Error).message;
    const [failed] = await db.update(approvalRequests).set({ status: 'failed', result: { error: message } }).where(eq(approvalRequests.id, id)).returning();
    return failed!;
  }
}
