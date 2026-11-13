import { and, asc, count, desc, eq, ilike, inArray, sql, type SQL } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import { assertInScope, scopeCondition } from '../auth/scope.ts';
import { onlineThresholdSeconds, type Config } from '../config.ts';
import { devicePatches, devicePatchState, devices } from '../db/schema.ts';
import { resolveTargets } from '../groups/filter.ts';
import { conflict, forbidden, HttpError, IdParams, Pagination, parse, Uuid } from '../http.ts';
import { startPatchScan } from '../patches/scan.ts';
import { PATCH_OSES } from '../patches/scripts.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';
import { csvCell } from './security.ts';

const DevicesQuery = Pagination.extend({
  search: z.string().max(100).optional(),
  filter: z.enum(['all', 'missing', 'security', 'reboot', 'never', 'failed']).default('all'),
});
const UpdatesQuery = Pagination.extend({ search: z.string().max(100).optional(), security: z.enum(['true', 'false']).optional() });
const ScanBody = z.object({
  targets: z.object({
    deviceIds: z.array(Uuid).max(10_000).default([]),
    groupIds: z.array(Uuid).max(500).default([]),
    allDevices: z.boolean().default(false),
  }),
});
const ExportQuery = z.object({ format: z.enum(['csv', 'json']).default('csv') });

const CRITICAL = sql`lower(${devicePatches.severity}) = 'critical' or ${devicePatches.classification} = 'Critical Updates'`;

export function patchRoutes(app: FastifyInstance, config: Config) {
  /** Per-device counts within the caller's scope. */
  async function deviceRows(scopeCond: SQL | undefined, q?: z.infer<typeof DevicesQuery>) {
    const counts = app.db
      .select({
        deviceId: devicePatches.deviceId,
        missing: sql<number>`count(*)::int`.as('missing'),
        security: sql<number>`count(*) filter (where ${devicePatches.security})::int`.as('security'),
        critical: sql<number>`count(*) filter (where ${CRITICAL})::int`.as('critical'),
        rebootUpdates: sql<number>`count(*) filter (where ${devicePatches.rebootRequired})::int`.as('reboot_updates'),
      })
      .from(devicePatches)
      .groupBy(devicePatches.deviceId)
      .as('c');
    const conds: (SQL | undefined)[] = [eq(devices.status, 'active'), inArray(devices.os, PATCH_OSES), scopeCond];
    if (q?.search) conds.push(ilike(devices.hostname, `%${q.search}%`));
    switch (q?.filter) {
      case 'missing':
        conds.push(sql`coalesce(${counts.missing}, 0) > 0`);
        break;
      case 'security':
        conds.push(sql`coalesce(${counts.security}, 0) > 0`);
        break;
      case 'reboot':
        conds.push(eq(devicePatchState.rebootPending, true));
        break;
      case 'never':
        conds.push(sql`${devicePatchState.lastScanAt} is null`);
        break;
      case 'failed':
        conds.push(eq(devicePatchState.lastScanStatus, 'failed'));
        break;
    }
    const base = app.db
      .select({
        deviceId: devices.id,
        hostname: devices.hostname,
        os: devices.os,
        osVersion: devices.osVersion,
        lastSeenAt: devices.lastSeenAt,
        source: devicePatchState.source,
        lastScanAt: devicePatchState.lastScanAt,
        lastScanStatus: devicePatchState.lastScanStatus,
        lastError: devicePatchState.lastError,
        rebootPending: sql<boolean>`coalesce(${devicePatchState.rebootPending}, false)`,
        missing: sql<number>`coalesce(${counts.missing}, 0)`,
        security: sql<number>`coalesce(${counts.security}, 0)`,
        critical: sql<number>`coalesce(${counts.critical}, 0)`,
      })
      .from(devices)
      .leftJoin(devicePatchState, eq(devicePatchState.deviceId, devices.id))
      .leftJoin(counts, eq(counts.deviceId, devices.id))
      .where(and(...conds));
    return base;
  }

  app.get('/patches/summary', { preHandler: app.requireScopedPermission('patches:read') }, async (req) => {
    const scope = await app.deviceScope(req, 'patches:read');
    const rows = await deviceRows(scopeCondition(scope, devices.id));
    const cutoff = Date.now() - Math.max(config.PATCH_SCAN_INTERVAL_HOURS, 24) * 2 * 3600_000;
    const top = await app.db
      .select({
        updateId: devicePatches.updateId,
        source: devicePatches.source,
        title: sql<string>`max(${devicePatches.title})`,
        kb: sql<string | null>`max(${devicePatches.kb})`,
        security: sql<boolean>`bool_or(${devicePatches.security})`,
        severity: sql<string>`max(${devicePatches.severity})`,
        devices: count(),
      })
      .from(devicePatches)
      .innerJoin(devices, eq(devices.id, devicePatches.deviceId))
      .where(and(eq(devices.status, 'active'), scopeCondition(scope, devices.id)))
      .groupBy(devicePatches.source, devicePatches.updateId)
      .orderBy(desc(sql`bool_or(${devicePatches.security})`), desc(count()))
      .limit(10);
    return {
      devices: rows.length,
      scanned: rows.filter((r) => r.lastScanAt).length,
      neverScanned: rows.filter((r) => !r.lastScanAt).length,
      scanFailed: rows.filter((r) => r.lastScanStatus === 'failed').length,
      stale: rows.filter((r) => r.lastScanAt && r.lastScanAt.getTime() < cutoff).length,
      upToDate: rows.filter((r) => r.lastScanStatus === 'ok' && r.missing === 0).length,
      withMissing: rows.filter((r) => r.missing > 0).length,
      withSecurity: rows.filter((r) => r.security > 0).length,
      withCritical: rows.filter((r) => r.critical > 0).length,
      rebootPending: rows.filter((r) => r.rebootPending).length,
      missingTotal: rows.reduce((a, r) => a + r.missing, 0),
      securityTotal: rows.reduce((a, r) => a + r.security, 0),
      scanIntervalHours: config.PATCH_SCAN_INTERVAL_HOURS,
      topUpdates: top,
    };
  });

  app.get('/patches/devices', { preHandler: app.requireScopedPermission('patches:read') }, async (req) => {
    const q = parse(DevicesQuery, req.query);
    const scope = await app.deviceScope(req, 'patches:read');
    const all = await deviceRows(scopeCondition(scope, devices.id), q);
    all.sort((a, b) => b.critical - a.critical || b.security - a.security || b.missing - a.missing || a.hostname.localeCompare(b.hostname));
    return { items: all.slice(q.offset, q.offset + q.limit), total: all.length };
  });

  app.get('/patches/updates', { preHandler: app.requireScopedPermission('patches:read') }, async (req) => {
    const q = parse(UpdatesQuery, req.query);
    const scope = await app.deviceScope(req, 'patches:read');
    const conds: (SQL | undefined)[] = [eq(devices.status, 'active'), scopeCondition(scope, devices.id)];
    if (q.search) conds.push(sql`(${devicePatches.title} ilike ${`%${q.search}%`} or ${devicePatches.kb} ilike ${`%${q.search}%`} or ${devicePatches.updateId} ilike ${`%${q.search}%`})`);
    if (q.security) conds.push(eq(devicePatches.security, q.security === 'true'));
    const items = await app.db
      .select({
        updateId: devicePatches.updateId,
        source: devicePatches.source,
        title: sql<string>`max(${devicePatches.title})`,
        kb: sql<string | null>`max(${devicePatches.kb})`,
        classification: sql<string>`max(${devicePatches.classification})`,
        severity: sql<string>`max(${devicePatches.severity})`,
        security: sql<boolean>`bool_or(${devicePatches.security})`,
        rebootRequired: sql<boolean>`bool_or(${devicePatches.rebootRequired})`,
        firstDetectedAt: sql<string>`min(${devicePatches.detectedAt})`,
        devices: count(),
      })
      .from(devicePatches)
      .innerJoin(devices, eq(devices.id, devicePatches.deviceId))
      .where(and(...conds))
      .groupBy(devicePatches.source, devicePatches.updateId)
      .orderBy(desc(sql`bool_or(${devicePatches.security})`), desc(count()), asc(sql`max(${devicePatches.title})`))
      .limit(q.limit)
      .offset(q.offset);
    return { items: items.map((i) => ({ ...i, firstDetectedAt: new Date(i.firstDetectedAt).toISOString() })) };
  });

  app.get('/devices/:id/patches', { preHandler: app.requireScopedPermission('patches:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    assertInScope(await app.deviceScope(req, 'patches:read'), id);
    const [state] = await app.db.select().from(devicePatchState).where(eq(devicePatchState.deviceId, id));
    const items = await app.db
      .select()
      .from(devicePatches)
      .where(eq(devicePatches.deviceId, id))
      .orderBy(desc(devicePatches.security), asc(devicePatches.title));
    return {
      state: state ?? { deviceId: id, source: null, lastScanAt: null, lastScanStatus: null, lastError: null, rebootPending: false, scanRequestedAt: null },
      items: items.map(({ id: _i, deviceId: _d, ...u }) => u),
    };
  });

  app.post('/patches/scan', { preHandler: app.requireScopedPermission('patches:execute') }, async (req, reply) => {
    const { targets } = parse(ScanBody, req.body);
    if (!targets.allDevices && !targets.deviceIds.length && !targets.groupIds.length) throw new HttpError(400, 'validation_error', 'No targets');
    const scope = await app.deviceScope(req, 'patches:execute');
    let ids = await resolveTargets(app.db, targets, onlineThresholdSeconds(config));
    if (!scope.all) {
      const outside = targets.deviceIds.filter((d) => !scope.ids.has(d));
      if (outside.length) throw forbidden(`${outside.length} device(s) are outside your permission scope`);
      ids = ids.filter((d) => scope.ids.has(d));
    }
    if (!ids.length) throw conflict('No matching devices');
    const r = await startPatchScan(app.db, ids, { trigger: 'patch_scan', triggeredBy: principalOf(req).userId, name: 'Patch-Scan' });
    if (!r.devices) throw conflict('None of the devices runs a supported operating system');
    await writeAudit(app.db, actorOf(req), { action: 'patches.scan', targetType: 'device', details: { devices: r.devices, runIds: r.runIds }, ip: req.ip });
    return reply.code(202).send(r);
  });

  app.get('/patches/export', { preHandler: app.requireScopedPermission('patches:read') }, async (req, reply) => {
    const { format } = parse(ExportQuery, req.query);
    const scope = await app.deviceScope(req, 'patches:read');
    const rows = (await deviceRows(scopeCondition(scope, devices.id))).sort((a, b) => a.hostname.localeCompare(b.hostname));
    await writeAudit(app.db, actorOf(req), { action: 'patches.export', details: { format, rows: rows.length }, ip: req.ip });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    if (format === 'json') {
      return reply.header('content-disposition', `attachment; filename="opencm-patchstand-${stamp}.json"`).send({ exportedAt: new Date().toISOString(), items: rows });
    }
    const header = ['hostname', 'os', 'osVersion', 'source', 'lastScanAt', 'lastScanStatus', 'missing', 'security', 'critical', 'rebootPending', 'lastSeenAt'];
    const lines = rows.map((r) =>
      [r.hostname, r.os, r.osVersion, r.source, r.lastScanAt?.toISOString(), r.lastScanStatus, r.missing, r.security, r.critical, r.rebootPending, r.lastSeenAt?.toISOString()].map(csvCell).join(';'),
    );
    return reply
      .header('content-type', 'text/csv; charset=utf-8')
      .header('content-disposition', `attachment; filename="opencm-patchstand-${stamp}.csv"`)
      .send(`\uFEFF${header.join(';')}\r\n${lines.join('\r\n')}\r\n`);
  });
}
