import { and, asc, desc, eq, inArray, type SQL } from 'drizzle-orm';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import { hasPermission, type Permission } from '../auth/permissions.ts';
import type { Config } from '../config.ts';
import { deployments, deviceGroups, jobRuns, packages, packageVersions, users } from '../db/schema.ts';
import { forbidden, HttpError, IdParams, notFound, Pagination, parse, Uuid } from '../http.ts';
import {
  cancelDeployment,
  createDeployment,
  pauseDeployment,
  promote,
  resumeDeployment,
  ringStats,
  startRing,
  type DeploymentRow,
} from '../packages/deploy.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';

const HHMM = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, 'HH:MM');
const Targets = z.object({
  deviceIds: z.array(Uuid).max(10_000).default([]),
  groupIds: z.array(Uuid).max(500).default([]),
  allDevices: z.boolean().default(false),
});
const Ring = z.object({
  name: z.string().trim().min(1).max(50),
  targets: Targets,
  delayHours: z.number().min(0).max(24 * 90).default(0),
  minSuccessPercent: z.number().min(0).max(100).default(90),
});
const DeploymentBody = z.object({
  name: z.string().trim().max(150).optional(),
  kind: z.enum(['package', 'os_updates']),
  packageVersionId: Uuid.nullable().optional(),
  action: z.enum(['install', 'uninstall']).default('install'),
  patchFilter: z
    .object({
      classification: z.enum(['critical', 'security', 'all']).default('security'),
      include: z.array(z.string().trim().min(1).max(300).regex(/^[A-Za-z0-9][A-Za-z0-9._+:@\/ -]*$/, 'invalid update id')).max(500).default([]),
      reboot: z.enum(['never', 'if_required']).default('never'),
    })
    .optional(),
  rings: z.array(Ring).min(1).max(10),
  options: z
    .object({
      maxRetries: z.number().int().min(0).max(10).optional(),
      retryDelaySeconds: z.number().int().min(0).max(86_400).optional(),
      timeoutSeconds: z.number().int().min(60).max(86_400).optional(),
      maintenanceWindow: z
        .object({ days: z.array(z.number().int().min(0).max(6)).min(1).max(7), start: HHMM, end: HHMM })
        .refine((w) => w.start !== w.end, 'start and end must differ')
        .nullable()
        .optional(),
      timezone: z.string().max(64).optional(),
    })
    .optional(),
});
const ListQuery = Pagination.extend({ kind: z.enum(['package', 'os_updates']).optional(), status: z.string().max(30).optional() });

type Kind = 'package' | 'os_updates';
const perm = (kind: string, action: 'read' | 'execute'): Permission => (kind === 'os_updates' ? `patches:${action}` : `software:${action}`) as Permission;

export function deploymentRoutes(app: FastifyInstance, config: Config) {
  function need(req: FastifyRequest, kind: string, action: 'read' | 'execute') {
    const p = perm(kind, action);
    if (!hasPermission(principalOf(req).grants, p)) throw forbidden(`Missing permission ${p}`);
  }

  async function load(id: string) {
    const [d] = await app.db.select().from(deployments).where(eq(deployments.id, id));
    if (!d) throw notFound('Deployment');
    return d;
  }

  async function detail(d: DeploymentRow) {
    const stats = await ringStats(app.db, d);
    const runs = await app.db
      .select({ id: jobRuns.id, ring: jobRuns.ring, name: jobRuns.name, status: jobRuns.status, createdAt: jobRuns.createdAt, finishedAt: jobRuns.finishedAt })
      .from(jobRuns)
      .where(eq(jobRuns.deploymentId, d.id))
      .orderBy(asc(jobRuns.createdAt));
    const pkg = d.packageVersionId
      ? (
          await app.db
            .select({ packageId: packages.id, name: packages.name, platform: packages.platform, version: packageVersions.version, type: packageVersions.type })
            .from(packageVersions)
            .innerJoin(packages, eq(packages.id, packageVersions.packageId))
            .where(eq(packageVersions.id, d.packageVersionId))
        )[0] ?? null
      : null;
    const groupIds = [...new Set(d.rings.flatMap((r) => r.targets.groupIds))];
    const groups = groupIds.length ? await app.db.select({ id: deviceGroups.id, name: deviceGroups.name }).from(deviceGroups).where(inArray(deviceGroups.id, groupIds)) : [];
    const [creator] = d.createdBy ? await app.db.select({ username: users.username }).from(users).where(eq(users.id, d.createdBy)) : [];
    const { steps, ...rest } = d;
    return {
      ...rest,
      platforms: Object.keys(steps),
      package: pkg,
      createdByName: creator?.username ?? null,
      rings: d.rings.map((r, i) => ({ ...r, groupNames: r.targets.groupIds.map((g) => groups.find((x) => x.id === g)?.name ?? g), stats: stats[i]! })),
      runs,
    };
  }

  app.get('/deployments', { preHandler: app.requireAuth }, async (req) => {
    const q = parse(ListQuery, req.query);
    const p = principalOf(req);
    const kinds = (['package', 'os_updates'] as Kind[]).filter((k) => (!q.kind || q.kind === k) && hasPermission(p.grants, perm(k, 'read')));
    if (!kinds.length) throw forbidden('Missing permission software:read or patches:read');
    const conds: SQL[] = [inArray(deployments.kind, kinds)];
    if (q.status) conds.push(eq(deployments.status, q.status));
    const rows = await app.db
      .select()
      .from(deployments)
      .where(and(...conds))
      .orderBy(desc(deployments.createdAt))
      .limit(q.limit)
      .offset(q.offset);
    const items = [];
    for (const d of rows) {
      const stats = await ringStats(app.db, d);
      const { steps: _s, ...rest } = d;
      const total = stats.reduce((a, s) => a + s.total - s.skipped, 0);
      const succeeded = stats.reduce((a, s) => a + s.succeeded, 0);
      const failed = stats.reduce((a, s) => a + s.failed, 0);
      items.push({ ...rest, ringCount: d.rings.length, currentRingName: d.rings[d.currentRing]?.name ?? null, progress: { total, succeeded, failed } });
    }
    return { items };
  });

  app.post('/deployments', { preHandler: app.requireAuth }, async (req, reply) => {
    const body = parse(DeploymentBody, req.body);
    need(req, body.kind, 'execute');
    if (body.kind === 'package' && !body.packageVersionId) throw new HttpError(400, 'validation_error', 'packageVersionId is required for package deployments');
    if (body.kind === 'os_updates' && body.action !== 'install') throw new HttpError(400, 'validation_error', 'OS updates can only be installed');
    for (const r of body.rings) if (!r.targets.allDevices && !r.targets.deviceIds.length && !r.targets.groupIds.length) throw new HttpError(400, 'validation_error', `Ring "${r.name}" has no targets`);
    const groupIds = [...new Set(body.rings.flatMap((r) => r.targets.groupIds))];
    if (groupIds.length) {
      const found = await app.db.select({ id: deviceGroups.id }).from(deviceGroups).where(inArray(deviceGroups.id, groupIds));
      if (found.length !== groupIds.length) throw new HttpError(400, 'invalid_reference', 'Unknown device group id in rings');
    }
    const me = principalOf(req).userId;
    const dep = await createDeployment(app.db, { ...body, patchFilter: body.patchFilter ?? null, options: body.options as never }, me);
    const audit = { kind: dep.kind, packageVersionId: dep.packageVersionId, action: dep.action, rings: dep.rings.map((r) => r.name) };
    await startRing(app.db, config, dep.id, -1, 0, me, ['created']);
    await writeAudit(app.db, actorOf(req), { action: 'deployment.create', targetType: 'deployment', targetId: dep.id, details: audit, ip: req.ip });
    return reply.code(201).send(await detail(await load(dep.id)));
  });

  app.get('/deployments/:id', { preHandler: app.requireAuth }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const d = await load(id);
    need(req, d.kind, 'read');
    return detail(d);
  });

  const control = (action: 'promote' | 'pause' | 'resume' | 'cancel') => async (req: FastifyRequest) => {
    const { id } = parse(IdParams, req.params);
    const d = await load(id);
    need(req, d.kind, 'execute');
    const me = principalOf(req).userId;
    let details: Record<string, unknown> = {};
    if (action === 'promote') details = await promote(app.db, config, id, me);
    else if (action === 'pause') await pauseDeployment(app.db, id);
    else if (action === 'resume') await resumeDeployment(app.db, id);
    else await cancelDeployment(app.db, id);
    await writeAudit(app.db, actorOf(req), { action: `deployment.${action}`, targetType: 'deployment', targetId: id, details: { name: d.name, ring: d.currentRing, ...details }, ip: req.ip });
    return detail(await load(id));
  };
  app.post('/deployments/:id/promote', { preHandler: app.requireAuth }, control('promote'));
  app.post('/deployments/:id/pause', { preHandler: app.requireAuth }, control('pause'));
  app.post('/deployments/:id/resume', { preHandler: app.requireAuth }, control('resume'));
  app.post('/deployments/:id/cancel', { preHandler: app.requireAuth }, control('cancel'));
}
