import { and, asc, count, desc, eq, gt, inArray, or } from 'drizzle-orm';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import { hasPermission, type Permission } from '../auth/permissions.ts';
import { onlineThresholdSeconds, type Config } from '../config.ts';
import type { Db } from '../db/client.ts';
import {
  customFields,
  deviceGroups,
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
} from '../db/schema.ts';
import { resolveTargets } from '../groups/filter.ts';
import { conflict, forbidden, HttpError, IdParams, notFound, Pagination, parse, Uuid } from '../http.ts';
import { cancelRun, cancelTasks, createRun, DEFAULT_OPTIONS, rerun, runJob, TERMINAL } from '../jobs/engine.ts';
import { resolveJobSteps } from '../jobs/steps.ts';
import { assertCron, isValidTimezone, nextCronRun } from '../jobs/schedule.ts';
import { hasAnyGrant, inScope } from '../auth/scope.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';

const HHMM = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, 'HH:MM');
const Options = z.object({
  timeoutSeconds: z.number().int().min(10).max(86_400).default(DEFAULT_OPTIONS.timeoutSeconds),
  maxRetries: z.number().int().min(0).max(10).default(DEFAULT_OPTIONS.maxRetries),
  retryDelaySeconds: z.number().int().min(0).max(86_400).default(DEFAULT_OPTIONS.retryDelaySeconds),
  stopOnError: z.boolean().default(true),
  maintenanceWindow: z
    .object({ days: z.array(z.number().int().min(0).max(6)).min(1).max(7), start: HHMM, end: HHMM })
    .refine((w) => w.start !== w.end, 'start and end must differ')
    .nullable()
    .default(null),
});
const Targets = z.object({
  deviceIds: z.array(Uuid).max(10_000).default([]),
  groupIds: z.array(Uuid).max(500).default([]),
  allDevices: z.boolean().default(false),
});
const Step = z.object({
  scriptId: Uuid,
  version: z.number().int().min(1).optional(), // default: latest approved version
  params: z.record(z.string(), z.unknown()).default({}),
  continueOnError: z.boolean().default(false),
  customFieldId: Uuid.nullable().default(null),
});
const TRIGGERS = ['manual', 'once', 'cron', 'agent_start', 'user_login'] as const;
const JobBody = z.object({
  name: z.string().trim().min(1).max(150),
  description: z.string().max(2000).default(''),
  enabled: z.boolean().default(true),
  trigger: z.enum(TRIGGERS),
  runAt: z.coerce.date().nullable().default(null),
  cron: z.string().max(100).nullable().default(null),
  timezone: z.string().max(64).default('UTC'),
  targets: Targets,
  options: Options.prefault({}),
  steps: z.array(Step).min(1).max(50),
});
// Explicit (no defaults!): with zod 4, `.partial()` still applies field defaults,
// which would silently reset omitted fields.
const JobPatch = z.object({
  name: z.string().trim().min(1).max(150).optional(),
  description: z.string().max(2000).optional(),
  enabled: z.boolean().optional(),
  trigger: z.enum(TRIGGERS).optional(),
  runAt: z.coerce.date().nullable().optional(),
  cron: z.string().max(100).nullable().optional(),
  timezone: z.string().max(64).optional(),
  targets: Targets.optional(),
  options: Options.optional(),
  steps: z.array(Step).min(1).max(50).optional(),
});
const RunBody = z.object({ deviceIds: z.array(Uuid).max(10_000).optional() });
const RerunBody = z.object({ onlyFailed: z.boolean().default(true) });
const OutputQuery = z.object({ after: z.coerce.number().int().min(0).default(0), limit: z.coerce.number().int().min(1).max(5000).default(1000) });
const RunsQuery = Pagination.extend({ jobId: Uuid.optional() });
const AdHocRun = z.object({
  version: z.number().int().min(1).optional(),
  targets: Targets,
  params: z.record(z.string(), z.unknown()).default({}),
  timeoutSeconds: z.number().int().min(10).max(86_400).default(3600),
});

type JobInput = z.infer<typeof JobBody>;

export function jobRoutes(app: FastifyInstance, config: Config) {
  const online = onlineThresholdSeconds(config);

  /**
   * Which runs/tasks a principal may see: global jobs:read → everything; otherwise
   * tasks on devices within the jobs:read / scripts:execute scope plus own runs.
   */
  async function runVisibility(req: FastifyRequest): Promise<{ all: boolean; ids: Set<string>; userId: string }> {
    const p = principalOf(req);
    if (!hasAnyGrant(p, 'jobs:read') && !hasAnyGrant(p, 'scripts:execute')) throw forbidden('Missing permission jobs:read');
    const a = await app.deviceScope(req, 'jobs:read');
    const b = await app.deviceScope(req, 'scripts:execute');
    return { all: a.all || b.all, ids: new Set([...a.ids, ...b.ids]), userId: p.userId };
  }

  async function assertRunVisible(req: FastifyRequest, run: { id: string; triggeredBy: string | null }) {
    const v = await runVisibility(req);
    if (v.all || run.triggeredBy === v.userId) return v;
    if (v.ids.size) {
      const [hit] = await app.db.select({ id: tasks.id }).from(tasks).where(and(eq(tasks.runId, run.id), inArray(tasks.deviceId, [...v.ids]))).limit(1);
      if (hit) return v;
    }
    throw notFound('Run');
  }

  /**
   * Controlling runs (cancel/rerun): global jobs:execute (scripts:execute for job-less
   * runs), own runs, or – for a single task – a device within the jobs:execute scope.
   */
  async function needsExec(req: FastifyRequest, run: { jobId: string | null; triggeredBy: string | null }, deviceId?: string) {
    const p = principalOf(req);
    const perms: Permission[] = run.jobId ? ['jobs:execute'] : ['jobs:execute', 'scripts:execute'];
    if (perms.some((x) => hasPermission(p.grants, x))) return;
    if (run.triggeredBy === p.userId && perms.some((x) => hasAnyGrant(p, x))) return;
    if (deviceId && inScope(await app.deviceScope(req, 'jobs:execute'), deviceId)) return;
    throw forbidden(`Missing permission ${perms.join(' or ')}`);
  }

  /** Restricts resolved targets to the principal's jobs:execute scope; explicit devices outside it → 403. */
  async function restrictToScope(req: FastifyRequest, resolved: string[], explicit: string[] = []): Promise<{ ids: string[]; global: boolean }> {
    const scope = await app.deviceScope(req, 'jobs:execute');
    if (scope.all) return { ids: resolved, global: true };
    const outside = explicit.filter((id) => !scope.ids.has(id));
    if (outside.length) throw forbidden(`${outside.length} device(s) are outside your permission scope`);
    const ids = resolved.filter((id) => scope.ids.has(id));
    if (!ids.length) throw conflict('None of the target devices is within your permission scope');
    return { ids, global: false };
  }

  // ------------------------------------------------------------ validation helpers

  const resolveSteps = (db: Db, steps: JobInput['steps']) => resolveJobSteps(db, steps);

  async function validateTargets(db: Db, t: JobTargets) {
    if (!t.allDevices && !t.deviceIds.length && !t.groupIds.length) throw new HttpError(400, 'validation_error', 'Job needs at least one target');
    if (t.deviceIds.length) {
      const found = await db.select({ id: devices.id }).from(devices).where(inArray(devices.id, t.deviceIds));
      if (found.length !== new Set(t.deviceIds).size) throw new HttpError(400, 'invalid_reference', 'Unknown device id in targets');
    }
    if (t.groupIds.length) {
      const found = await db.select({ id: deviceGroups.id }).from(deviceGroups).where(inArray(deviceGroups.id, t.groupIds));
      if (found.length !== new Set(t.groupIds).size) throw new HttpError(400, 'invalid_reference', 'Unknown device group id in targets');
    }
  }

  function scheduleFields(j: Pick<JobInput, 'trigger' | 'runAt' | 'cron' | 'timezone' | 'enabled'>, now = new Date()) {
    if (!isValidTimezone(j.timezone)) throw new HttpError(400, 'validation_error', `Unknown time zone "${j.timezone}"`);
    if (j.trigger === 'once') {
      if (!j.runAt) throw new HttpError(400, 'validation_error', 'runAt is required for trigger "once"');
      return { runAt: j.runAt, cron: null, nextRunAt: j.runAt };
    }
    if (j.trigger === 'cron') {
      if (!j.cron) throw new HttpError(400, 'validation_error', 'cron is required for trigger "cron"');
      try {
        assertCron(j.cron, j.timezone);
      } catch (e) {
        throw new HttpError(400, 'validation_error', `Invalid cron expression: ${(e as Error).message}`);
      }
      return { runAt: null, cron: j.cron.trim(), nextRunAt: nextCronRun(j.cron, j.timezone, now) };
    }
    return { runAt: null, cron: null, nextRunAt: null };
  }

  // ------------------------------------------------------------ loading

  async function loadJob(db: Db, id: string) {
    const [j] = await db.select().from(jobs).where(eq(jobs.id, id));
    if (!j) throw notFound('Job');
    const steps = await db
      .select({
        position: jobSteps.position,
        scriptId: scripts.id,
        scriptName: scripts.name,
        interpreter: scripts.interpreter,
        scriptVersionId: scriptVersions.id,
        version: scriptVersions.version,
        versionStatus: scriptVersions.status,
        params: jobSteps.params,
        continueOnError: jobSteps.continueOnError,
        customFieldId: jobSteps.customFieldId,
      })
      .from(jobSteps)
      .innerJoin(scriptVersions, eq(scriptVersions.id, jobSteps.scriptVersionId))
      .innerJoin(scripts, eq(scripts.id, scriptVersions.scriptId))
      .where(eq(jobSteps.jobId, id))
      .orderBy(asc(jobSteps.position));
    const [last] = await db.select().from(jobRuns).where(eq(jobRuns.jobId, id)).orderBy(desc(jobRuns.createdAt)).limit(1);
    return { ...j, steps, lastRun: last ? await withCounts(db, last) : null };
  }

  async function countsFor(db: Db, runIds: string[]) {
    if (!runIds.length) return new Map<string, Record<string, number>>();
    const rows = await db
      .select({ runId: tasks.runId, status: tasks.status, n: count() })
      .from(tasks)
      .where(inArray(tasks.runId, runIds))
      .groupBy(tasks.runId, tasks.status);
    const map = new Map<string, Record<string, number>>();
    for (const r of rows) {
      const m = map.get(r.runId) ?? {};
      m[r.status] = r.n;
      map.set(r.runId, m);
    }
    return map;
  }

  const runSummary = (r: typeof jobRuns.$inferSelect, counts: Record<string, number>) => {
    const { steps, ...rest } = r;
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    return {
      ...rest,
      steps: (steps as RunStep[]).map(({ content: _c, seal: _s, ...s }) => s),
      counts: { total, ...counts },
    };
  };

  async function withCounts(db: Db, r: typeof jobRuns.$inferSelect) {
    return runSummary(r, (await countsFor(db, [r.id])).get(r.id) ?? {});
  }

  async function writeSteps(db: Db, jobId: string, steps: Awaited<ReturnType<typeof resolveSteps>>) {
    await db.delete(jobSteps).where(eq(jobSteps.jobId, jobId));
    await db.insert(jobSteps).values(steps.map((s, position) => ({ jobId, position, ...s })));
  }

  // ------------------------------------------------------------ jobs

  app.get('/jobs', { preHandler: app.requirePermission('jobs:read') }, async () => {
    const rows = await app.db.select().from(jobs).orderBy(asc(jobs.name));
    const stepCounts = await app.db.select({ jobId: jobSteps.jobId, n: count() }).from(jobSteps).groupBy(jobSteps.jobId);
    return { items: rows.map((j) => ({ ...j, stepCount: stepCounts.find((s) => s.jobId === j.id)?.n ?? 0 })) };
  });

  app.post('/jobs', { preHandler: app.requirePermission('jobs:create') }, async (req, reply) => {
    const body = parse(JobBody, req.body);
    await validateTargets(app.db, body.targets);
    const steps = await resolveSteps(app.db, body.steps);
    const sched = scheduleFields(body);
    if (body.trigger === 'once' && body.runAt && body.runAt.getTime() < Date.now() - 60_000) throw new HttpError(400, 'validation_error', 'runAt lies in the past');
    const id = await app.db.transaction(async (tx) => {
      const [j] = await tx
        .insert(jobs)
        .values({
          name: body.name,
          description: body.description,
          enabled: body.enabled,
          trigger: body.trigger,
          timezone: body.timezone,
          targets: body.targets,
          options: body.options as JobOptions,
          createdBy: principalOf(req).userId,
          ...sched,
        })
        .returning({ id: jobs.id });
      await writeSteps(tx as unknown as Db, j!.id, steps);
      return j!.id;
    });
    await writeAudit(app.db, actorOf(req), {
      action: 'job.create',
      targetType: 'job',
      targetId: id,
      details: { name: body.name, trigger: body.trigger, targets: body.targets, steps: steps.length },
      ip: req.ip,
    });
    return reply.code(201).send(await loadJob(app.db, id));
  });

  app.get('/jobs/:id', { preHandler: app.requirePermission('jobs:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    return loadJob(app.db, id);
  });

  app.patch('/jobs/:id', { preHandler: app.requirePermission('jobs:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(JobPatch, req.body);
    const current = await loadJob(app.db, id);
    if (body.targets) await validateTargets(app.db, body.targets);
    const steps = body.steps ? await resolveSteps(app.db, body.steps) : null;
    const merged = {
      trigger: body.trigger ?? (current.trigger as JobInput['trigger']),
      runAt: body.runAt !== undefined ? body.runAt : current.runAt,
      cron: body.cron !== undefined ? body.cron : current.cron,
      timezone: body.timezone ?? current.timezone,
      enabled: body.enabled ?? current.enabled,
    };
    const scheduleChanged = ['trigger', 'runAt', 'cron', 'timezone', 'enabled'].some((k) => k in body);
    const sched = scheduleChanged ? scheduleFields(merged) : {};
    await app.db.transaction(async (tx) => {
      await tx
        .update(jobs)
        .set({
          ...(body.name !== undefined && { name: body.name }),
          ...(body.description !== undefined && { description: body.description }),
          ...(body.enabled !== undefined && { enabled: body.enabled }),
          ...(body.trigger !== undefined && { trigger: body.trigger }),
          ...(body.timezone !== undefined && { timezone: body.timezone }),
          ...(body.targets && { targets: body.targets }),
          ...(body.options && { options: body.options as JobOptions }),
          ...sched,
          updatedAt: new Date(),
        })
        .where(eq(jobs.id, id));
      if (steps) await writeSteps(tx as unknown as Db, id, steps);
    });
    await writeAudit(app.db, actorOf(req), { action: 'job.update', targetType: 'job', targetId: id, details: { fields: Object.keys(body) }, ip: req.ip });
    return loadJob(app.db, id);
  });

  app.delete('/jobs/:id', { preHandler: app.requirePermission('jobs:delete') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const j = await loadJob(app.db, id);
    const active = await app.db.select({ id: jobRuns.id }).from(jobRuns).where(and(eq(jobRuns.jobId, id), eq(jobRuns.status, 'running')));
    for (const r of active) await cancelRun(app.db, r.id);
    await app.db.delete(jobs).where(eq(jobs.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'job.delete', targetType: 'job', targetId: id, details: { name: j.name }, ip: req.ip });
    return reply.code(204).send();
  });

  app.get('/jobs/:id/targets', { preHandler: app.requirePermission('jobs:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const j = await loadJob(app.db, id);
    const ids = await resolveTargets(app.db, j.targets, online);
    const items = ids.length
      ? await app.db.select({ id: devices.id, hostname: devices.hostname, os: devices.os }).from(devices).where(inArray(devices.id, ids)).orderBy(asc(devices.hostname))
      : [];
    return { items, total: items.length };
  });

  app.post('/jobs/:id/run', { preHandler: app.requireScopedPermission('jobs:execute') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(RunBody, req.body ?? {});
    const [job] = await app.db.select().from(jobs).where(eq(jobs.id, id));
    if (!job) throw notFound('Job');
    let resolved = await resolveTargets(app.db, job.targets, online);
    if (body.deviceIds) resolved = resolved.filter((d) => body.deviceIds!.includes(d));
    const scoped = await restrictToScope(req, resolved, body.deviceIds);
    const deviceIds = scoped.global ? body.deviceIds : scoped.ids;
    const run = await runJob(app.db, config, id, 'manual', principalOf(req).userId, deviceIds);
    await writeAudit(app.db, actorOf(req), { action: 'job.run', targetType: 'job', targetId: id, details: { runId: run.id, deviceIds: deviceIds ?? 'all targets' }, ip: req.ip });
    return reply.code(201).send(await withCounts(app.db, run));
  });

  app.get('/jobs/:id/runs', { preHandler: app.requirePermission('jobs:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const q = parse(Pagination, req.query);
    const rows = await app.db.select().from(jobRuns).where(eq(jobRuns.jobId, id)).orderBy(desc(jobRuns.createdAt)).limit(q.limit).offset(q.offset);
    const counts = await countsFor(app.db, rows.map((r) => r.id));
    const [total] = await app.db.select({ n: count() }).from(jobRuns).where(eq(jobRuns.jobId, id));
    return { items: rows.map((r) => runSummary(r, counts.get(r.id) ?? {})), total: total?.n ?? 0 };
  });

  // Ad-hoc execution of an approved script on any targets (no job is created).
  app.post('/scripts/:id/run', { preHandler: app.requireScopedPermission('jobs:execute') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(AdHocRun, req.body);
    await validateTargets(app.db, body.targets);
    const [script] = await app.db.select().from(scripts).where(eq(scripts.id, id));
    if (!script) throw notFound('Script');
    const [step] = await resolveSteps(app.db, [{ scriptId: id, version: body.version, params: body.params, continueOnError: false, customFieldId: null }]);
    const [v] = await app.db.select().from(scriptVersions).where(eq(scriptVersions.id, step!.scriptVersionId));
    const scope = await app.deviceScope(req, 'jobs:execute');
    if (body.targets.allDevices && !scope.all) throw forbidden('"All devices" requires a global jobs:execute permission');
    const { ids: deviceIds } = await restrictToScope(req, await resolveTargets(app.db, body.targets, online), body.targets.deviceIds);
    const run = await createRun(app.db, {
      jobId: null,
      name: `Ad-hoc: ${script.name} v${v!.version}`,
      trigger: 'manual',
      triggeredBy: principalOf(req).userId,
      steps: [
        {
          position: 0,
          scriptId: script.id,
          scriptName: script.name,
          scriptVersionId: v!.id,
          version: v!.version,
          interpreter: script.interpreter,
          content: v!.content,
          sha256: v!.sha256,
          params: step!.params,
          continueOnError: false,
          customFieldId: null,
        },
      ],
      options: { ...DEFAULT_OPTIONS, timeoutSeconds: body.timeoutSeconds, timezone: 'UTC' },
      deviceIds,
    });
    await writeAudit(app.db, actorOf(req), {
      action: 'script.run',
      targetType: 'script',
      targetId: id,
      details: { version: v!.version, targets: body.targets, devices: deviceIds.length, runId: run.id },
      ip: req.ip,
    });
    return reply.code(201).send(await withCounts(app.db, run));
  });

  // ------------------------------------------------------------ runs

  app.get('/runs', { preHandler: app.requireAuth }, async (req) => {
    const vis = await runVisibility(req);
    const q = parse(RunsQuery, req.query);
    const visible = vis.all
      ? undefined
      : or(
          eq(jobRuns.triggeredBy, vis.userId),
          vis.ids.size ? inArray(jobRuns.id, app.db.select({ id: tasks.runId }).from(tasks).where(inArray(tasks.deviceId, [...vis.ids]))) : undefined,
        );
    const where = and(q.jobId ? eq(jobRuns.jobId, q.jobId) : undefined, visible);
    const rows = await app.db.select().from(jobRuns).where(where).orderBy(desc(jobRuns.createdAt)).limit(q.limit).offset(q.offset);
    const counts = await countsFor(app.db, rows.map((r) => r.id));
    const [total] = await app.db.select({ n: count() }).from(jobRuns).where(where);
    return { items: rows.map((r) => runSummary(r, counts.get(r.id) ?? {})), total: total?.n ?? 0 };
  });

  async function loadRun(id: string) {
    const [r] = await app.db.select().from(jobRuns).where(eq(jobRuns.id, id));
    if (!r) throw notFound('Run');
    return r;
  }

  app.get('/runs/:id', { preHandler: app.requireAuth }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const run = await loadRun(id);
    await assertRunVisible(req, run);
    return withCounts(app.db, run);
  });

  app.get('/runs/:id/tasks', { preHandler: app.requireAuth }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const run = await loadRun(id);
    const vis = await assertRunVisible(req, run);
    const restrict = vis.all || run.triggeredBy === vis.userId ? undefined : inArray(tasks.deviceId, [...vis.ids]);
    const items = await app.db
      .select({
        id: tasks.id,
        deviceId: tasks.deviceId,
        hostname: devices.hostname,
        os: devices.os,
        status: tasks.status,
        attempt: tasks.attempt,
        exitCode: tasks.exitCode,
        error: tasks.error,
        notBefore: tasks.notBefore,
        dispatchedAt: tasks.dispatchedAt,
        startedAt: tasks.startedAt,
        finishedAt: tasks.finishedAt,
        cancelRequested: tasks.cancelRequested,
      })
      .from(tasks)
      .innerJoin(devices, eq(devices.id, tasks.deviceId))
      .where(and(eq(tasks.runId, id), restrict))
      .orderBy(asc(devices.hostname));
    return { items };
  });

  app.post('/runs/:id/cancel', { preHandler: app.requireAuth }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const run = await loadRun(id);
    await assertRunVisible(req, run);
    await needsExec(req, run);
    await cancelRun(app.db, id);
    await writeAudit(app.db, actorOf(req), { action: 'run.cancel', targetType: 'run', targetId: id, ip: req.ip });
    return withCounts(app.db, await loadRun(id));
  });

  app.post('/runs/:id/rerun', { preHandler: app.requireAuth }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(RerunBody, req.body ?? {});
    const run = await loadRun(id);
    await assertRunVisible(req, run);
    await needsExec(req, run);
    const next = await rerun(app.db, id, body.onlyFailed, principalOf(req).userId);
    await writeAudit(app.db, actorOf(req), { action: 'run.rerun', targetType: 'run', targetId: id, details: { newRunId: next.id, onlyFailed: body.onlyFailed }, ip: req.ip });
    return reply.code(201).send(await withCounts(app.db, next));
  });

  // ------------------------------------------------------------ tasks

  async function loadTask(id: string) {
    const [row] = await app.db
      .select({ task: tasks, hostname: devices.hostname, os: devices.os, runName: jobRuns.name, jobId: jobRuns.jobId, triggeredBy: jobRuns.triggeredBy, steps: jobRuns.steps })
      .from(tasks)
      .innerJoin(devices, eq(devices.id, tasks.deviceId))
      .innerJoin(jobRuns, eq(jobRuns.id, tasks.runId))
      .where(eq(tasks.id, id));
    if (!row) throw notFound('Task');
    return row;
  }

  /** Tasks are visible with global rights, in own runs, or on devices within the scope. */
  async function loadVisibleTask(req: FastifyRequest, id: string) {
    const r = await loadTask(id);
    const vis = await runVisibility(req);
    if (!vis.all && r.triggeredBy !== vis.userId && !vis.ids.has(r.task.deviceId)) throw notFound('Task');
    return r;
  }

  app.get('/tasks/:id', { preHandler: app.requireAuth }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const r = await loadVisibleTask(req, id);
    return {
      ...r.task,
      hostname: r.hostname,
      os: r.os,
      runName: r.runName,
      jobId: r.jobId,
      steps: (r.steps as RunStep[]).map((s) => ({ position: s.position, scriptName: s.scriptName, version: s.version, interpreter: s.interpreter })),
    };
  });

  app.get('/tasks/:id/output', { preHandler: app.requireAuth }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const q = parse(OutputQuery, req.query);
    const r = await loadVisibleTask(req, id);
    const items = await app.db
      .select({ id: taskOutput.id, stream: taskOutput.stream, data: taskOutput.data, at: taskOutput.at })
      .from(taskOutput)
      .where(and(eq(taskOutput.taskId, id), gt(taskOutput.id, q.after)))
      .orderBy(asc(taskOutput.id))
      .limit(q.limit);
    const done = (TERMINAL as readonly string[]).includes(r.task.status);
    return { items, nextCursor: items.at(-1)?.id ?? q.after, status: r.task.status, done: done && items.length < q.limit };
  });

  app.post('/tasks/:id/cancel', { preHandler: app.requireAuth }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const r = await loadVisibleTask(req, id);
    await needsExec(req, r, r.task.deviceId);
    if ((TERMINAL as readonly string[]).includes(r.task.status)) throw conflict(`Task is already ${r.task.status}`);
    await cancelTasks(app.db, eq(tasks.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'task.cancel', targetType: 'task', targetId: id, ip: req.ip });
    const after = await loadTask(id);
    return { id, status: after.task.status, cancelRequested: after.task.cancelRequested };
  });
}
