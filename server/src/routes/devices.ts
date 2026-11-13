import { and, asc, count, desc, eq, gte, ilike, isNull, lt, or, sql, type SQL } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import { onlineThresholdSeconds, type Config } from '../config.ts';
import type { Db } from '../db/client.ts';
import { deviceGroupMembers, deviceGroups, deviceHistory, deviceInventory, devices, deviceSoftware } from '../db/schema.ts';
import { IdParams, notFound, Pagination, parse } from '../http.ts';
import { assertInScope, scopeCondition } from '../auth/scope.ts';
import { actorOf } from '../plugins/auth.ts';
import { OS_VALUES } from './enrollment.ts';

const boolParam = z.enum(['true', 'false']).transform((v) => v === 'true');

const ListQuery = Pagination.extend({
  search: z.string().max(200).optional(),
  os: z.enum(OS_VALUES).optional(),
  status: z.enum(['active', 'revoked']).optional(),
  online: boolParam.optional(),
  sort: z.enum(['hostname', 'lastSeenAt', 'enrolledAt']).default('hostname'),
});

const HistoryQuery = Pagination.extend({ category: z.string().max(50).optional() });
const SoftwareQuery = z.object({ search: z.string().max(200).optional() });

const escapeLike = (s: string) => s.replace(/[\\%_]/g, (c) => `\\${c}`);

export function deviceRoutes(app: FastifyInstance, config: Config) {
  const threshold = onlineThresholdSeconds(config);
  const onlineExpr = sql<boolean>`coalesce(${devices.lastSeenAt} > now() - make_interval(secs => ${threshold}), false)`;

  const columns = {
    id: devices.id,
    hostname: devices.hostname,
    os: devices.os,
    osVersion: devices.osVersion,
    arch: devices.arch,
    agentVersion: devices.agentVersion,
    status: devices.status,
    online: onlineExpr,
    manufacturer: devices.manufacturer,
    model: devices.model,
    serialNumber: devices.serialNumber,
    loggedOnUser: devices.loggedOnUser,
    lastIp: devices.lastIp,
    lastSeenAt: devices.lastSeenAt,
    lastInventoryAt: devices.lastInventoryAt,
    enrolledAt: devices.enrolledAt,
  };

  async function loadDevice(db: Db, id: string) {
    const [d] = await db
      .select({ ...columns, certExpiresAt: devices.certExpiresAt, certSerial: devices.certSerial, inventoryRequested: devices.inventoryRequested })
      .from(devices)
      .where(eq(devices.id, id));
    if (!d) throw notFound('Device');
    const groups = await db
      .select({ id: deviceGroups.id, name: deviceGroups.name })
      .from(deviceGroupMembers)
      .innerJoin(deviceGroups, eq(deviceGroups.id, deviceGroupMembers.deviceGroupId))
      .where(eq(deviceGroupMembers.deviceId, id));
    return { ...d, groups };
  }

  app.get('/devices', { preHandler: app.requireScopedPermission('devices:read') }, async (req) => {
    const q = parse(ListQuery, req.query);
    const conds: SQL[] = [];
    const scopeCond = scopeCondition(await app.deviceScope(req, 'devices:read'), devices.id);
    if (scopeCond) conds.push(scopeCond);
    if (q.search) {
      const p = `%${escapeLike(q.search)}%`;
      conds.push(or(ilike(devices.hostname, p), ilike(devices.serialNumber, p), ilike(devices.loggedOnUser, p), ilike(devices.model, p))!);
    }
    if (q.os) conds.push(eq(devices.os, q.os));
    if (q.status) conds.push(eq(devices.status, q.status));
    if (q.online === true) conds.push(gte(devices.lastSeenAt, sql`now() - make_interval(secs => ${threshold})`));
    if (q.online === false) conds.push(or(isNull(devices.lastSeenAt), lt(devices.lastSeenAt, sql`now() - make_interval(secs => ${threshold})`))!);
    const where = conds.length ? and(...conds) : undefined;
    const order =
      q.sort === 'lastSeenAt' ? sql`${devices.lastSeenAt} desc nulls last` : q.sort === 'enrolledAt' ? desc(devices.enrolledAt) : asc(devices.hostname);
    const items = await app.db.select(columns).from(devices).where(where).orderBy(order).limit(q.limit).offset(q.offset);
    const [total] = await app.db.select({ n: count() }).from(devices).where(where);
    return { items, total: total?.n ?? 0 };
  });

  app.get('/devices/:id', { preHandler: app.requireScopedPermission('devices:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    assertInScope(await app.deviceScope(req, 'devices:read'), id);
    return loadDevice(app.db, id);
  });

  app.get('/devices/:id/inventory', { preHandler: app.requireScopedPermission('inventory:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    assertInScope(await app.deviceScope(req, 'inventory:read'), id);
    await loadDevice(app.db, id);
    const [inv] = await app.db.select().from(deviceInventory).where(eq(deviceInventory.deviceId, id));
    if (!inv) throw notFound('Inventory');
    return { collectedAt: inv.collectedAt, receivedAt: inv.receivedAt, ...inv.data };
  });

  app.get('/devices/:id/software', { preHandler: app.requireScopedPermission('inventory:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    assertInScope(await app.deviceScope(req, 'inventory:read'), id);
    const q = parse(SoftwareQuery, req.query);
    await loadDevice(app.db, id);
    const where = q.search
      ? and(eq(deviceSoftware.deviceId, id), or(ilike(deviceSoftware.name, `%${escapeLike(q.search)}%`), ilike(deviceSoftware.publisher, `%${escapeLike(q.search)}%`)))
      : eq(deviceSoftware.deviceId, id);
    const items = await app.db
      .select({
        name: deviceSoftware.name,
        version: deviceSoftware.version,
        publisher: deviceSoftware.publisher,
        installDate: deviceSoftware.installDate,
        source: deviceSoftware.source,
        arch: deviceSoftware.arch,
      })
      .from(deviceSoftware)
      .where(where)
      .orderBy(sql`lower(${deviceSoftware.name})`, deviceSoftware.version);
    return { items };
  });

  app.get('/devices/:id/history', { preHandler: app.requireScopedPermission('inventory:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    assertInScope(await app.deviceScope(req, 'inventory:read'), id);
    const q = parse(HistoryQuery, req.query);
    await loadDevice(app.db, id);
    const where = q.category ? and(eq(deviceHistory.deviceId, id), eq(deviceHistory.category, q.category)) : eq(deviceHistory.deviceId, id);
    const items = await app.db
      .select({
        id: deviceHistory.id,
        at: deviceHistory.at,
        category: deviceHistory.category,
        change: deviceHistory.change,
        itemKey: deviceHistory.itemKey,
        oldValue: deviceHistory.oldValue,
        newValue: deviceHistory.newValue,
      })
      .from(deviceHistory)
      .where(where)
      .orderBy(desc(deviceHistory.id))
      .limit(q.limit)
      .offset(q.offset);
    const [total] = await app.db.select({ n: count() }).from(deviceHistory).where(where);
    return { items, total: total?.n ?? 0 };
  });

  app.post('/devices/:id/inventory-request', { preHandler: app.requireScopedPermission('inventory:update') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    assertInScope(await app.deviceScope(req, 'inventory:update'), id);
    await loadDevice(app.db, id);
    await app.db.update(devices).set({ inventoryRequested: true }).where(eq(devices.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'device.inventory_request', targetType: 'device', targetId: id, ip: req.ip });
    return reply.code(202).send({ requested: true });
  });

  app.post('/devices/:id/revoke', { preHandler: app.requireScopedPermission('devices:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    assertInScope(await app.deviceScope(req, 'devices:update'), id);
    const d = await loadDevice(app.db, id);
    await app.db.update(devices).set({ status: 'revoked', certFingerprint: null, updatedAt: new Date() }).where(eq(devices.id, id));
    await writeAudit(app.db, actorOf(req), {
      action: 'device.revoke',
      targetType: 'device',
      targetId: id,
      details: { hostname: d.hostname, certSerial: d.certSerial },
      ip: req.ip,
    });
    return loadDevice(app.db, id);
  });

  app.delete('/devices/:id', { preHandler: app.requireScopedPermission('devices:delete') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    assertInScope(await app.deviceScope(req, 'devices:delete'), id);
    const d = await loadDevice(app.db, id);
    await app.db.delete(devices).where(eq(devices.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'device.delete', targetType: 'device', targetId: id, details: { hostname: d.hostname }, ip: req.ip });
    return reply.code(204).send();
  });
}
