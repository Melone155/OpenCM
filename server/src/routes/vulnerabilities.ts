import { and, asc, count, desc, eq, ilike, inArray, isNull, or, sql, type SQL } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import { hasPermission } from '../auth/permissions.ts';
import type { Config } from '../config.ts';
import { cpeRules, devices, deviceSoftware, deviceVulnerabilities, feedState, jobs, jobSteps, vulnerabilities } from '../db/schema.ts';
import { conflict, forbidden, HttpError, IdParams, notFound, Pagination, parse, Uuid } from '../http.ts';
import { DEFAULT_OPTIONS, runJob } from '../jobs/engine.ts';
import { resolveJobSteps } from '../jobs/steps.ts';
import { SCRIPT_TEMPLATES } from '../jobs/templates.ts';
import { assertInScope, scopeCondition } from '../auth/scope.ts';
import { createApproval, massApprovalNeeded } from '../approvals.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';
import { getSecurity, needsApproval } from '../settings.ts';
import { productIndex } from '../vuln/evaluate.ts';
import { FEEDS, requestSync } from '../vuln/feeds.ts';
import { ensureBuiltinRules, loadRules, mapSoftware, ruleMatches, suggestProducts, type CpeRule } from '../vuln/mapping.ts';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'] as const;
const CveParams = z.object({ cveId: z.string().regex(/^CVE-\d{4}-\d{4,}$/i).transform((s) => s.toUpperCase()) });
const csv = <T extends string>(values: readonly T[]) =>
  z
    .string()
    .optional()
    .transform((s) => (s ? s.split(',').map((x) => x.trim().toUpperCase()).filter(Boolean) : []))
    .pipe(z.array(z.enum(values as unknown as [T, ...T[]])));
const confidenceCsv = z
  .string()
  .optional()
  .transform((s) => (s ? s.split(',').map((x) => x.trim().toLowerCase()) : []))
  .pipe(z.array(z.enum(['high', 'medium', 'low'])));

const ListQuery = Pagination.extend({
  severity: csv(SEVERITIES),
  confidence: confidenceCsv,
  kev: z.enum(['true', 'false']).optional(),
  search: z.string().max(200).optional(),
  deviceId: Uuid.optional(),
  includeAccepted: z.enum(['true', 'false']).default('false'),
});
const Accept = z.object({ accepted: z.boolean(), reason: z.string().max(1000).optional() });
const Remediation = z.object({
  scriptId: Uuid,
  version: z.number().int().min(1).optional(),
  params: z.record(z.string(), z.unknown()).default({}),
  name: z.string().trim().min(1).max(150).optional(),
  deviceIds: z.array(Uuid).max(10_000).optional(),
  runNow: z.boolean().default(false),
  timeoutSeconds: z.number().int().min(10).max(86_400).default(3600),
});
const DeviceVulnQuery = z.object({ status: z.enum(['open', 'fixed', 'all']).default('open') });
const SoftwareQuery = Pagination.extend({
  search: z.string().max(200).optional(),
  mapping: z.enum(['all', 'mapped', 'unmapped', 'ignored']).default('all'),
});
const Glob = z.string().trim().min(1).max(200);
const SOURCES = ['registry', 'msi', 'appx', 'dpkg', 'rpm', 'app'] as const;
const RuleBody = z
  .object({
    namePattern: Glob,
    publisherPattern: Glob.nullable().default(null),
    source: z.enum(SOURCES).nullable().default(null),
    vendor: z.string().trim().min(1).max(200).nullable().default(null),
    product: z.string().trim().min(1).max(200).nullable().default(null),
    ignore: z.boolean().default(false),
    priority: z.number().int().min(0).max(1000).default(10),
    enabled: z.boolean().default(true),
    note: z.string().max(500).default(''),
  })
  .refine((r) => r.ignore || (r.vendor && r.product), 'vendor and product are required unless ignore is set');
const RulePatch = z.object({
  namePattern: Glob.optional(),
  publisherPattern: Glob.nullable().optional(),
  source: z.enum(SOURCES).nullable().optional(),
  vendor: z.string().trim().min(1).max(200).nullable().optional(),
  product: z.string().trim().min(1).max(200).nullable().optional(),
  ignore: z.boolean().optional(),
  priority: z.number().int().min(0).max(1000).optional(),
  enabled: z.boolean().optional(),
  note: z.string().max(500).optional(),
});
const RuleTest = z.object({ namePattern: Glob, publisherPattern: Glob.nullable().default(null), source: z.enum(SOURCES).nullable().default(null) });
const SyncBody = z.object({ feeds: z.array(z.enum(FEEDS)).min(1).default([...FEEDS]) });

const vulnCols = {
  cveId: vulnerabilities.cveId,
  description: vulnerabilities.description,
  published: vulnerabilities.published,
  lastModified: vulnerabilities.lastModified,
  cvssScore: vulnerabilities.cvssScore,
  cvssSeverity: vulnerabilities.cvssSeverity,
  cvssVersion: vulnerabilities.cvssVersion,
  cvssVector: vulnerabilities.cvssVector,
  kev: vulnerabilities.kev,
  kevDateAdded: vulnerabilities.kevDateAdded,
  kevDueDate: vulnerabilities.kevDueDate,
  kevRansomware: vulnerabilities.kevRansomware,
  epss: vulnerabilities.epss,
  epssPercentile: vulnerabilities.epssPercentile,
  acceptedAt: vulnerabilities.acceptedAt,
  acceptedReason: vulnerabilities.acceptedReason,
};

const RISK_ORDER = [desc(vulnerabilities.kev), sql`${vulnerabilities.cvssScore} desc nulls last`, sql`${vulnerabilities.epss} desc nulls last`];

export function vulnerabilityRoutes(app: FastifyInstance, config: Config) {
  const dv = deviceVulnerabilities;
  const openActive = and(eq(dv.status, 'open'), eq(devices.status, 'active'));

  // ------------------------------------------------------------ overview

  app.get('/vulnerabilities/summary', { preHandler: app.requireScopedPermission('vulnerabilities:read') }, async (req) => {
    const scopeCond = scopeCondition(await app.deviceScope(req, 'vulnerabilities:read'), dv.deviceId);
    const notAccepted = and(isNull(vulnerabilities.acceptedAt), scopeCond)!;
    const bySeverity = await app.db
      .select({ severity: vulnerabilities.cvssSeverity, cves: sql<number>`count(distinct ${dv.cveId})::int`, devices: sql<number>`count(distinct ${dv.deviceId})::int` })
      .from(dv)
      .innerJoin(vulnerabilities, eq(vulnerabilities.cveId, dv.cveId))
      .innerJoin(devices, eq(devices.id, dv.deviceId))
      .where(and(openActive, notAccepted))
      .groupBy(vulnerabilities.cvssSeverity);
    const [totals] = await app.db
      .select({
        cves: sql<number>`count(distinct ${dv.cveId})::int`,
        devices: sql<number>`count(distinct ${dv.deviceId})::int`,
        findings: sql<number>`count(*)::int`,
        kevCves: sql<number>`count(distinct ${dv.cveId}) filter (where ${vulnerabilities.kev})::int`,
        kevDevices: sql<number>`count(distinct ${dv.deviceId}) filter (where ${vulnerabilities.kev})::int`,
        kevOverdue: sql<number>`count(distinct ${dv.cveId}) filter (where ${vulnerabilities.kev} and ${vulnerabilities.kevDueDate} < to_char(now(), 'YYYY-MM-DD'))::int`,
      })
      .from(dv)
      .innerJoin(vulnerabilities, eq(vulnerabilities.cveId, dv.cveId))
      .innerJoin(devices, eq(devices.id, dv.deviceId))
      .where(and(openActive, notAccepted));
    const [mirror] = await app.db.select({ cves: count(), kev: sql<number>`count(*) filter (where ${vulnerabilities.kev})::int` }).from(vulnerabilities);
    const feeds = await app.db.select().from(feedState).orderBy(asc(feedState.name));
    return {
      openCves: totals?.cves ?? 0,
      affectedDevices: totals?.devices ?? 0,
      openFindings: totals?.findings ?? 0,
      kev: { cves: totals?.kevCves ?? 0, devices: totals?.kevDevices ?? 0, overdue: totals?.kevOverdue ?? 0 },
      bySeverity: Object.fromEntries(SEVERITIES.map((s) => [s, bySeverity.find((b) => b.severity === s) ?? { severity: s, cves: 0, devices: 0 }]).map(([k, v]) => [k, { cves: (v as { cves: number }).cves, devices: (v as { devices: number }).devices }])),
      unscored: bySeverity.find((b) => b.severity === null)?.cves ?? 0,
      mirror: { cves: mirror?.cves ?? 0, kev: mirror?.kev ?? 0 },
      feeds: feeds.map(({ lockedUntil, ...f }) => ({ ...f, running: !!lockedUntil && lockedUntil > new Date() })),
    };
  });

  app.get('/vulnerabilities', { preHandler: app.requireScopedPermission('vulnerabilities:read') }, async (req) => {
    const q = parse(ListQuery, req.query);
    const conds: SQL[] = [openActive!];
    const scopeCond = scopeCondition(await app.deviceScope(req, 'vulnerabilities:read'), dv.deviceId);
    if (scopeCond) conds.push(scopeCond);
    if (q.includeAccepted !== 'true') conds.push(isNull(vulnerabilities.acceptedAt));
    if (q.severity.length) conds.push(inArray(vulnerabilities.cvssSeverity, q.severity));
    if (q.confidence.length) conds.push(inArray(dv.confidence, q.confidence));
    if (q.kev) conds.push(eq(vulnerabilities.kev, q.kev === 'true'));
    if (q.deviceId) conds.push(eq(dv.deviceId, q.deviceId));
    if (q.search) {
      const p = `%${q.search.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
      conds.push(or(ilike(vulnerabilities.cveId, p), ilike(vulnerabilities.description, p), ilike(dv.product, p), ilike(dv.softwareName, p))!);
    }
    const where = and(...conds);
    const items = await app.db
      .select({
        ...vulnCols,
        affectedDevices: sql<number>`count(distinct ${dv.deviceId})::int`,
        products: sql<string[]>`array_agg(distinct ${dv.vendor} || ':' || ${dv.product})`,
        confidence: sql<string>`min(case ${dv.confidence} when 'high' then 1 when 'medium' then 2 else 3 end)::int`,
      })
      .from(dv)
      .innerJoin(vulnerabilities, eq(vulnerabilities.cveId, dv.cveId))
      .innerJoin(devices, eq(devices.id, dv.deviceId))
      .where(where)
      .groupBy(vulnerabilities.cveId)
      .orderBy(...RISK_ORDER, desc(sql`count(distinct ${dv.deviceId})`), asc(vulnerabilities.cveId))
      .limit(q.limit)
      .offset(q.offset);
    const [total] = await app.db
      .select({ n: sql<number>`count(distinct ${dv.cveId})::int` })
      .from(dv)
      .innerJoin(vulnerabilities, eq(vulnerabilities.cveId, dv.cveId))
      .innerJoin(devices, eq(devices.id, dv.deviceId))
      .where(where);
    const conf = ['high', 'medium', 'low'];
    return { items: items.map((i) => ({ ...i, confidence: conf[Number(i.confidence) - 1] ?? 'low' })), total: total?.n ?? 0 };
  });

  async function loadVuln(cveId: string) {
    const [v] = await app.db.select().from(vulnerabilities).where(eq(vulnerabilities.cveId, cveId));
    if (!v) throw notFound('Vulnerability');
    return v;
  }

  app.get('/vulnerabilities/:cveId', { preHandler: app.requireScopedPermission('vulnerabilities:read') }, async (req) => {
    const { cveId } = parse(CveParams, req.params);
    const v = await loadVuln(cveId);
    const scopeCond = scopeCondition(await app.deviceScope(req, 'vulnerabilities:read'), dv.deviceId);
    const affected = await app.db
      .select({
        deviceId: dv.deviceId,
        hostname: devices.hostname,
        os: devices.os,
        softwareName: dv.softwareName,
        softwareVersion: dv.softwareVersion,
        vendor: dv.vendor,
        product: dv.product,
        confidence: dv.confidence,
        status: dv.status,
        firstSeen: dv.firstSeen,
        lastSeen: dv.lastSeen,
        fixedAt: dv.fixedAt,
      })
      .from(dv)
      .innerJoin(devices, eq(devices.id, dv.deviceId))
      .where(and(eq(dv.cveId, cveId), eq(devices.status, 'active'), scopeCond))
      .orderBy(asc(dv.status), asc(devices.hostname));
    return { ...v, affected };
  });

  app.patch('/vulnerabilities/:cveId', { preHandler: app.requirePermission('vulnerabilities:update') }, async (req) => {
    const { cveId } = parse(CveParams, req.params);
    const body = parse(Accept, req.body);
    await loadVuln(cveId);
    if (body.accepted && !body.reason) throw new HttpError(400, 'validation_error', 'A reason is required to accept a risk');
    await app.db
      .update(vulnerabilities)
      .set(
        body.accepted
          ? { acceptedAt: new Date(), acceptedBy: principalOf(req).userId, acceptedReason: body.reason ?? null }
          : { acceptedAt: null, acceptedBy: null, acceptedReason: null },
      )
      .where(eq(vulnerabilities.cveId, cveId));
    await writeAudit(app.db, actorOf(req), {
      action: body.accepted ? 'vulnerability.accept' : 'vulnerability.unaccept',
      targetType: 'vulnerability',
      targetId: cveId,
      details: { reason: body.reason ?? null },
      ip: req.ip,
    });
    return loadVuln(cveId);
  });

  app.post('/vulnerabilities/:cveId/remediation', { preHandler: app.requirePermission('jobs:create') }, async (req, reply) => {
    const { cveId } = parse(CveParams, req.params);
    const body = parse(Remediation, req.body);
    if (body.runNow && !hasPermission(principalOf(req).grants, 'jobs:execute')) throw forbidden('Missing permission jobs:execute');
    await loadVuln(cveId);
    const open = await app.db
      .selectDistinct({ deviceId: dv.deviceId })
      .from(dv)
      .innerJoin(devices, eq(devices.id, dv.deviceId))
      .where(and(eq(dv.cveId, cveId), openActive));
    let deviceIds = open.map((o) => o.deviceId);
    if (body.deviceIds) deviceIds = deviceIds.filter((id) => body.deviceIds!.includes(id));
    if (!deviceIds.length) throw conflict('No affected devices (with open findings) to remediate');
    const [step] = await resolveJobSteps(app.db, [{ scriptId: body.scriptId, version: body.version, params: body.params, continueOnError: false, customFieldId: null }]);
    const jobId = await app.db.transaction(async (tx) => {
      const [j] = await tx
        .insert(jobs)
        .values({
          name: body.name ?? `Behebung ${cveId}`,
          description: `Automatisch erzeugt aus ${cveId} für ${deviceIds.length} betroffene Geräte.`,
          trigger: 'manual',
          targets: { deviceIds, groupIds: [], allDevices: false },
          options: { ...DEFAULT_OPTIONS, timeoutSeconds: body.timeoutSeconds },
          createdBy: principalOf(req).userId,
        })
        .returning({ id: jobs.id });
      await tx.insert(jobSteps).values({ jobId: j!.id, position: 0, ...step! });
      return j!.id;
    });
    let run: { id: string } | null = null;
    let approvalId: string | null = null;
    if (body.runNow) {
      if (await massApprovalNeeded(app.db, config, principalOf(req).userId, deviceIds, false)) {
        const [job] = await app.db.select({ updatedAt: jobs.updatedAt }).from(jobs).where(eq(jobs.id, jobId));
        approvalId = (
          await createApproval(app.db, {
            action: 'remediation.run',
            summary: `Behebung ${cveId} auf ${deviceIds.length} Geräten ausführen`,
            payload: { jobId, jobUpdatedAt: job!.updatedAt.toISOString() },
            deviceCount: deviceIds.length,
            requestedBy: principalOf(req).userId,
          })
        ).id;
      } else {
        run = await runJob(app.db, config, jobId, 'manual', principalOf(req).userId);
      }
    }
    await writeAudit(app.db, actorOf(req), {
      action: 'vulnerability.remediation',
      targetType: 'vulnerability',
      targetId: cveId,
      details: { jobId, devices: deviceIds.length, scriptId: body.scriptId, runId: run?.id ?? null, approvalId },
      ip: req.ip,
    });
    return reply.code(201).send({ jobId, runId: run?.id ?? null, approvalId, devices: deviceIds.length });
  });

  app.get('/devices/:id/vulnerabilities', { preHandler: app.requireScopedPermission('vulnerabilities:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    assertInScope(await app.deviceScope(req, 'vulnerabilities:read'), id);
    const q = parse(DeviceVulnQuery, req.query);
    const [d] = await app.db.select({ id: devices.id }).from(devices).where(eq(devices.id, id));
    if (!d) throw notFound('Device');
    const items = await app.db
      .select({
        ...vulnCols,
        softwareName: dv.softwareName,
        softwareVersion: dv.softwareVersion,
        vendor: dv.vendor,
        product: dv.product,
        confidence: dv.confidence,
        status: dv.status,
        firstSeen: dv.firstSeen,
        fixedAt: dv.fixedAt,
      })
      .from(dv)
      .innerJoin(vulnerabilities, eq(vulnerabilities.cveId, dv.cveId))
      .where(and(eq(dv.deviceId, id), q.status === 'all' ? undefined : eq(dv.status, q.status)))
      .orderBy(...RISK_ORDER, asc(dv.cveId));
    return { items };
  });

  // ------------------------------------------------------------ fleet software & CPE rules

  app.get('/software', { preHandler: app.requireScopedPermission('inventory:read') }, async (req) => {
    const q = parse(SoftwareQuery, req.query);
    const scopeCond = scopeCondition(await app.deviceScope(req, 'inventory:read'), deviceSoftware.deviceId);
    const p = q.search ? `%${q.search.replace(/[\\%_]/g, (c) => `\\${c}`)}%` : null;
    const rows = await app.db
      .select({
        name: deviceSoftware.name,
        publisher: deviceSoftware.publisher,
        source: deviceSoftware.source,
        deviceCount: sql<number>`count(distinct ${deviceSoftware.deviceId})::int`,
        versions: sql<string[]>`array_agg(distinct ${deviceSoftware.version})`,
      })
      .from(deviceSoftware)
      .innerJoin(devices, and(eq(devices.id, deviceSoftware.deviceId), eq(devices.status, 'active')))
      .where(and(p ? or(ilike(deviceSoftware.name, p), ilike(deviceSoftware.publisher, p)) : undefined, scopeCond))
      .groupBy(deviceSoftware.name, deviceSoftware.publisher, deviceSoftware.source)
      .orderBy(desc(sql`count(distinct ${deviceSoftware.deviceId})`), asc(deviceSoftware.name));
    const rules = await loadRules(app.db);
    const index = await productIndex(app.db);
    const mapped = rows.map((r) => {
      const m = mapSoftware(r, rules, index);
      const mapping = !m ? null : 'ignored' in m ? { ignored: true as const, ruleId: m.ruleId } : m;
      return { ...r, versions: [...r.versions].sort().slice(0, 20), mapping };
    });
    const filtered = mapped.filter((r) =>
      q.mapping === 'mapped' ? r.mapping && !('ignored' in r.mapping) : q.mapping === 'unmapped' ? !r.mapping : q.mapping === 'ignored' ? r.mapping && 'ignored' in r.mapping : true,
    );
    const page = filtered.slice(q.offset, q.offset + q.limit).map((r) => ({ ...r, suggestions: r.mapping ? [] : suggestProducts(r, index, 5) }));
    return { items: page, total: filtered.length };
  });

  app.get('/cpe-rules', { preHandler: app.requirePermission('vulnerabilities:read') }, async () => {
    await ensureBuiltinRules(app.db);
    return { items: await app.db.select().from(cpeRules).orderBy(asc(cpeRules.priority), asc(cpeRules.origin), asc(cpeRules.namePattern)) };
  });

  app.post('/cpe-rules', { preHandler: app.requirePermission('vulnerabilities:update') }, async (req, reply) => {
    const body = parse(RuleBody, req.body);
    const [r] = await app.db
      .insert(cpeRules)
      .values({ ...body, vendor: body.ignore ? null : body.vendor?.toLowerCase() ?? null, product: body.ignore ? null : body.product?.toLowerCase() ?? null, origin: 'user' })
      .returning();
    await requestSync(app.db, []);
    await writeAudit(app.db, actorOf(req), { action: 'cpe_rule.create', targetType: 'cpe_rule', targetId: r!.id, details: body, ip: req.ip });
    return reply.code(201).send(r);
  });

  app.patch('/cpe-rules/:id', { preHandler: app.requirePermission('vulnerabilities:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(RulePatch, req.body);
    const [existing] = await app.db.select().from(cpeRules).where(eq(cpeRules.id, id));
    if (!existing) throw notFound('CPE rule');
    // built-in rules can only be enabled/disabled or re-prioritised
    if (existing.origin === 'builtin' && Object.keys(body).some((k) => !['enabled', 'priority'].includes(k))) {
      throw conflict('Built-in rules can only be enabled/disabled or re-prioritised – create a user rule to override');
    }
    const merged = { ...existing, ...body };
    if (!merged.ignore && !(merged.vendor && merged.product)) throw new HttpError(400, 'validation_error', 'vendor and product are required unless ignore is set');
    const [r] = await app.db
      .update(cpeRules)
      .set({ ...body, ...(body.vendor && { vendor: body.vendor.toLowerCase() }), ...(body.product && { product: body.product.toLowerCase() }) })
      .where(eq(cpeRules.id, id))
      .returning();
    await requestSync(app.db, []);
    await writeAudit(app.db, actorOf(req), { action: 'cpe_rule.update', targetType: 'cpe_rule', targetId: id, details: body, ip: req.ip });
    return r;
  });

  app.delete('/cpe-rules/:id', { preHandler: app.requirePermission('vulnerabilities:update') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const [existing] = await app.db.select().from(cpeRules).where(eq(cpeRules.id, id));
    if (!existing) throw notFound('CPE rule');
    if (existing.origin === 'builtin') throw conflict('Built-in rules cannot be deleted – disable them instead');
    await app.db.delete(cpeRules).where(eq(cpeRules.id, id));
    await requestSync(app.db, []);
    await writeAudit(app.db, actorOf(req), { action: 'cpe_rule.delete', targetType: 'cpe_rule', targetId: id, ip: req.ip });
    return reply.code(204).send();
  });

  app.post('/cpe-rules/test', { preHandler: app.requirePermission('vulnerabilities:read') }, async (req) => {
    const body = parse(RuleTest, req.body);
    const rule: CpeRule = { id: 'test', ...body, vendor: null, product: null, ignore: false, priority: 0, enabled: true };
    const rows = await app.db
      .selectDistinct({ name: deviceSoftware.name, publisher: deviceSoftware.publisher, source: deviceSoftware.source })
      .from(deviceSoftware)
      .limit(50_000);
    const hits = rows.filter((r) => ruleMatches(rule, r));
    return { total: hits.length, items: hits.slice(0, 100) };
  });

  // ------------------------------------------------------------ feeds

  app.get('/vulnerability-feeds', { preHandler: app.requirePermission('vulnerabilities:read') }, async () => {
    const rows = await app.db.select().from(feedState).orderBy(asc(feedState.name));
    return { enabled: config.VULN_FEEDS_ENABLED, items: rows.map(({ lockedUntil, ...f }) => ({ ...f, running: !!lockedUntil && lockedUntil > new Date() })) };
  });

  app.post('/vulnerability-feeds/sync', { preHandler: app.requirePermission('vulnerabilities:update') }, async (req, reply) => {
    const body = parse(SyncBody, req.body ?? {});
    await requestSync(app.db, body.feeds);
    await writeAudit(app.db, actorOf(req), { action: 'vulnerability_feeds.sync_request', details: { feeds: body.feeds }, ip: req.ip });
    return reply.code(202).send({ requested: body.feeds });
  });

  app.get('/script-templates', { preHandler: app.requirePermission('scripts:read') }, async () => ({ items: SCRIPT_TEMPLATES }));

}
