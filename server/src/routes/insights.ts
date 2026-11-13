import { and, desc, eq, or } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { APPROVER_PERMISSIONS } from '../approvals.ts';
import { writeAudit } from '../audit.ts';
import { hasPermission, type Permission } from '../auth/permissions.ts';
import { hasAnyGrant } from '../auth/scope.ts';
import type { Config } from '../config.ts';
import { approvalMetrics, assetMetrics, deploymentMetrics, deviceMetrics, integrityMetrics, licenseMetrics, METRIC_KEYS, metricTrends, patchMetrics, taskMetrics, vulnMetrics } from '../dashboard.ts';
import { securityMetrics } from '../security/posture.ts';
import { reports, users, type ReportFilter } from '../db/schema.ts';
import { forbidden, IdParams, notFound, parse } from '../http.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';
import { describeSources, reportSources, runReport } from '../reports.ts';
import { csvCell } from './security.ts';

const Filter = z.object({
  field: z.string().max(60),
  op: z.enum(['eq', 'ne', 'contains', 'starts', 'gt', 'gte', 'lt', 'lte', 'in', 'empty', 'notempty']),
  value: z.union([z.string().max(500), z.number(), z.boolean(), z.null(), z.array(z.union([z.string().max(500), z.number()])).max(500)]).optional(),
});
const Sort = z.object({ field: z.string().max(60), dir: z.enum(['asc', 'desc']).default('asc') });
const Definition = z.object({
  source: z.string().max(40),
  columns: z.array(z.string().max(60)).max(40).default([]),
  filters: z.array(Filter).max(20).default([]),
  sort: Sort.nullable().default(null),
});
const Preview = Definition.extend({ limit: z.number().int().min(1).max(1000).default(200) });
const ReportBody = Definition.extend({
  name: z.string().trim().min(1).max(150),
  description: z.string().max(2000).default(''),
  shared: z.boolean().default(false),
});
const ReportPatch = z.object({
  name: z.string().trim().min(1).max(150).optional(),
  description: z.string().max(2000).optional(),
  shared: z.boolean().optional(),
  source: z.string().max(40).optional(),
  columns: z.array(z.string().max(60)).max(40).optional(),
  filters: z.array(Filter).max(20).optional(),
  sort: Sort.nullable().optional(),
});
const RunQuery = z.object({ format: z.enum(['json', 'csv']).default('json'), limit: z.coerce.number().int().min(1).max(100_000).default(10_000) });
const DashQuery = z.object({ days: z.coerce.number().int().min(7).max(365).default(30) });

/** Which permission a (global) trend needs. */
const TREND_PERMISSION: Record<string, Permission> = {
  devices: 'devices:read',
  vuln: 'vulnerabilities:read',
  patches: 'patches:read',
  tasks: 'jobs:read',
  integrity: 'audit:read',
  licenses: 'licenses:read',
  security: 'inventory:read',
};

export function insightRoutes(app: FastifyInstance, config: Config) {
  // ------------------------------------------------------------ dashboard

  app.get('/dashboard', { preHandler: app.requireAuth }, async (req) => {
    const p = principalOf(req);
    const { days } = parse(DashQuery, req.query);
    const out: Record<string, unknown> = { generatedAt: new Date().toISOString() };
    if (hasAnyGrant(p, 'devices:read')) out.devices = await deviceMetrics(app.db, config, await app.deviceScope(req, 'devices:read'));
    if (hasAnyGrant(p, 'vulnerabilities:read')) out.vulnerabilities = await vulnMetrics(app.db, await app.deviceScope(req, 'vulnerabilities:read'));
    if (hasAnyGrant(p, 'patches:read')) out.patches = await patchMetrics(app.db, await app.deviceScope(req, 'patches:read'));
    if (hasAnyGrant(p, 'jobs:read')) out.tasks = await taskMetrics(app.db, await app.deviceScope(req, 'jobs:read'));
    if (hasPermission(p.grants, 'software:read') || hasPermission(p.grants, 'patches:read')) out.deployments = await deploymentMetrics(app.db);
    if (APPROVER_PERMISSIONS.some((x) => hasPermission(p.grants, x))) out.approvals = await approvalMetrics(app.db);
    if (hasPermission(p.grants, 'audit:read')) out.integrity = await integrityMetrics(app.db);
    if (hasPermission(p.grants, 'licenses:read')) out.licenses = await licenseMetrics(app.db);
    if (hasAnyGrant(p, 'inventory:read')) out.security = await securityMetrics(app.db, await app.deviceScope(req, 'inventory:read'));
    if (hasPermission(p.grants, 'assets:read')) out.assets = await assetMetrics(app.db);
    // trends are fleet-wide: only for globally entitled users
    const keys = METRIC_KEYS.filter((k) => hasPermission(p.grants, TREND_PERMISSION[k.split('.')[0]!]!));
    out.trends = await metricTrends(app.db, keys, days);
    return out;
  });

  // ------------------------------------------------------------ reports

  const mayRead = (req: FastifyRequest) => (perm: Permission) => hasAnyGrant(principalOf(req), perm);

  async function execute(req: FastifyRequest, def: { source: string; columns: string[]; filters: ReportFilter[]; sort: { field: string; dir: 'asc' | 'desc' } | null }, limit: number) {
    const source = reportSources(config)[def.source];
    if (source && !hasAnyGrant(principalOf(req), source.permission)) throw forbidden(`Missing permission ${source.permission}`);
    const scope = source?.deviceId ? await app.deviceScope(req, source.permission) : null;
    return runReport(app.db, config, { ...def, limit }, scope);
  }

  app.get('/report-sources', { preHandler: app.requirePermission('reports:read') }, async (req) => ({ items: describeSources(config, mayRead(req)) }));

  app.post('/reports/preview', { preHandler: app.requirePermission('reports:read') }, async (req) => {
    const body = parse(Preview, req.body);
    return execute(req, body, body.limit);
  });

  async function loadReport(req: FastifyRequest, id: string) {
    const p = principalOf(req);
    const [r] = await app.db.select().from(reports).where(eq(reports.id, id));
    if (!r || (!r.shared && r.createdBy !== p.userId)) throw notFound('Report');
    return r;
  }
  const mayEdit = (req: FastifyRequest, r: typeof reports.$inferSelect) => {
    const p = principalOf(req);
    if (r.createdBy !== p.userId && !hasPermission(p.grants, 'reports:update')) throw forbidden('Only the owner (or reports:update) may change this report');
  };

  app.get('/reports', { preHandler: app.requirePermission('reports:read') }, async (req) => {
    const p = principalOf(req);
    const rows = await app.db
      .select({ r: reports, owner: users.username })
      .from(reports)
      .leftJoin(users, eq(users.id, reports.createdBy))
      .where(or(eq(reports.shared, true), eq(reports.createdBy, p.userId)))
      .orderBy(desc(reports.updatedAt));
    const sources = reportSources(config);
    return { items: rows.map(({ r, owner }) => ({ ...r, ownerName: owner, sourceLabel: sources[r.source]?.label ?? r.source, mine: r.createdBy === p.userId })) };
  });

  app.post('/reports', { preHandler: app.requirePermission('reports:create') }, async (req, reply) => {
    const body = parse(ReportBody, req.body);
    await execute(req, body, 1); // validates source, columns, filters and permission
    const [r] = await app.db
      .insert(reports)
      .values({ ...body, filters: body.filters as ReportFilter[], createdBy: principalOf(req).userId })
      .returning();
    await writeAudit(app.db, actorOf(req), { action: 'report.create', targetType: 'report', targetId: r!.id, details: { name: body.name, source: body.source, shared: body.shared }, ip: req.ip });
    return reply.code(201).send(r);
  });

  app.get('/reports/:id', { preHandler: app.requirePermission('reports:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    return loadReport(req, id);
  });

  app.patch('/reports/:id', { preHandler: app.requirePermission('reports:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const r = await loadReport(req, id);
    mayEdit(req, r);
    const body = parse(ReportPatch, req.body);
    const next = { source: body.source ?? r.source, columns: body.columns ?? r.columns, filters: (body.filters ?? r.filters) as ReportFilter[], sort: body.sort === undefined ? r.sort : body.sort };
    await execute(req, next, 1);
    const [u] = await app.db
      .update(reports)
      .set({ ...body, filters: next.filters, updatedAt: new Date() })
      .where(and(eq(reports.id, id)))
      .returning();
    await writeAudit(app.db, actorOf(req), { action: 'report.update', targetType: 'report', targetId: id, details: { fields: Object.keys(body) }, ip: req.ip });
    return u;
  });

  app.delete('/reports/:id', { preHandler: app.requirePermission('reports:read') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const r = await loadReport(req, id);
    const p = principalOf(req);
    if (r.createdBy !== p.userId && !hasPermission(p.grants, 'reports:delete')) throw forbidden('Only the owner (or reports:delete) may delete this report');
    await app.db.delete(reports).where(eq(reports.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'report.delete', targetType: 'report', targetId: id, details: { name: r.name }, ip: req.ip });
    return reply.code(204).send();
  });

  app.get('/reports/:id/run', { preHandler: app.requirePermission('reports:read') }, async (req: FastifyRequest, reply: FastifyReply) => {
    const { id } = parse(IdParams, req.params);
    const q = parse(RunQuery, req.query);
    const r = await loadReport(req, id);
    const result = await execute(req, { source: r.source, columns: r.columns, filters: r.filters, sort: r.sort ?? null }, q.limit);
    if (q.format === 'json') return { report: { id: r.id, name: r.name }, ...result };
    await writeAudit(app.db, actorOf(req), { action: 'report.export', targetType: 'report', targetId: id, details: { rows: result.rows.length, format: 'csv' }, ip: req.ip });
    const header = result.columns.map((c) => csvCell(c.label)).join(';');
    const lines = result.rows.map((row) => result.columns.map((c) => csvCell(row[c.key])).join(';'));
    const safeName = r.name.replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60) || 'bericht';
    return reply
      .header('content-type', 'text/csv; charset=utf-8')
      .header('content-disposition', `attachment; filename="${safeName}-${new Date().toISOString().slice(0, 10)}.csv"`)
      .send(`\uFEFF${header}\r\n${lines.join('\r\n')}\r\n`);
  });
}
