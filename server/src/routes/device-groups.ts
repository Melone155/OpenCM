import { and, asc, count, eq, inArray, sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import { onlineThresholdSeconds, type Config } from '../config.ts';
import { deviceGroupMembers, deviceGroups, devices, jobs } from '../db/schema.ts';
import { FilterSchema, filterSql, groupMemberIds } from '../groups/filter.ts';
import { conflict, HttpError, IdParams, isUniqueViolation, notFound, Pagination, parse, Uuid } from '../http.ts';
import { actorOf } from '../plugins/auth.ts';

const CreateGroup = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('static'),
    name: z.string().trim().min(1).max(100),
    description: z.string().max(500).default(''),
    deviceIds: z.array(Uuid).max(10_000).default([]),
  }),
  z.object({
    kind: z.literal('dynamic'),
    name: z.string().trim().min(1).max(100),
    description: z.string().max(500).default(''),
    filter: FilterSchema,
  }),
]);
const UpdateGroup = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  description: z.string().max(500).optional(),
  filter: FilterSchema.optional(),
});
const Members = z.object({ deviceIds: z.array(Uuid).max(10_000) });
const Preview = z.object({ filter: FilterSchema });

const deviceCols = { id: devices.id, hostname: devices.hostname, os: devices.os, osVersion: devices.osVersion, loggedOnUser: devices.loggedOnUser, lastSeenAt: devices.lastSeenAt };

export function deviceGroupRoutes(app: FastifyInstance, config: Config) {
  const online = onlineThresholdSeconds(config);

  async function load(id: string) {
    const [g] = await app.db.select().from(deviceGroups).where(eq(deviceGroups.id, id));
    if (!g) throw notFound('Device group');
    const memberCount = (await groupMemberIds(app.db, id, online)).length;
    return { ...g, memberCount };
  }

  async function assertDevicesExist(ids: string[]) {
    if (!ids.length) return;
    const found = await app.db.select({ id: devices.id }).from(devices).where(inArray(devices.id, ids));
    if (found.length !== new Set(ids).size) throw new HttpError(400, 'invalid_reference', 'Unknown device id');
  }

  app.get('/device-groups', { preHandler: app.requirePermission('device_groups:read') }, async () => {
    const groups = await app.db.select().from(deviceGroups).orderBy(asc(deviceGroups.name));
    const items = [];
    for (const g of groups) items.push({ ...g, memberCount: (await groupMemberIds(app.db, g.id, online)).length });
    return { items };
  });

  app.post('/device-groups', { preHandler: app.requirePermission('device_groups:create') }, async (req, reply) => {
    const body = parse(CreateGroup, req.body);
    if (body.kind === 'static') await assertDevicesExist(body.deviceIds);
    let id: string;
    try {
      id = await app.db.transaction(async (tx) => {
        const [g] = await tx
          .insert(deviceGroups)
          .values({ name: body.name, description: body.description, kind: body.kind, filter: body.kind === 'dynamic' ? body.filter : null })
          .returning({ id: deviceGroups.id });
        if (body.kind === 'static' && body.deviceIds.length) {
          await tx.insert(deviceGroupMembers).values([...new Set(body.deviceIds)].map((deviceId) => ({ deviceGroupId: g!.id, deviceId })));
        }
        return g!.id;
      });
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Device group "${body.name}" already exists`);
      throw err;
    }
    await writeAudit(app.db, actorOf(req), { action: 'device_group.create', targetType: 'device_group', targetId: id, details: { name: body.name, kind: body.kind }, ip: req.ip });
    return reply.code(201).send(await load(id));
  });

  app.post('/device-groups/preview', { preHandler: app.requirePermission('device_groups:read') }, async (req) => {
    const { filter } = parse(Preview, req.body);
    const where = and(eq(devices.status, 'active'), filterSql(filter, online));
    const items = await app.db.select(deviceCols).from(devices).where(where).orderBy(asc(devices.hostname)).limit(50);
    const [total] = await app.db.select({ n: count() }).from(devices).where(where);
    return { items, total: total?.n ?? 0 };
  });

  app.get('/device-groups/:id', { preHandler: app.requirePermission('device_groups:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    return load(id);
  });

  app.patch('/device-groups/:id', { preHandler: app.requirePermission('device_groups:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(UpdateGroup, req.body);
    const g = await load(id);
    if (body.filter && g.kind !== 'dynamic') throw conflict('Only dynamic groups have a filter');
    try {
      await app.db
        .update(deviceGroups)
        .set({ ...body, updatedAt: new Date() })
        .where(eq(deviceGroups.id, id));
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Device group "${body.name}" already exists`);
      throw err;
    }
    await writeAudit(app.db, actorOf(req), { action: 'device_group.update', targetType: 'device_group', targetId: id, details: body, ip: req.ip });
    return load(id);
  });

  app.put('/device-groups/:id/members', { preHandler: app.requirePermission('device_groups:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const { deviceIds } = parse(Members, req.body);
    const g = await load(id);
    if (g.kind !== 'static') throw conflict('Members of dynamic groups are determined by the filter');
    await assertDevicesExist(deviceIds);
    await app.db.transaction(async (tx) => {
      await tx.delete(deviceGroupMembers).where(eq(deviceGroupMembers.deviceGroupId, id));
      if (deviceIds.length) await tx.insert(deviceGroupMembers).values([...new Set(deviceIds)].map((deviceId) => ({ deviceGroupId: id, deviceId })));
    });
    await writeAudit(app.db, actorOf(req), { action: 'device_group.members', targetType: 'device_group', targetId: id, details: { count: deviceIds.length }, ip: req.ip });
    return load(id);
  });

  app.get('/device-groups/:id/devices', { preHandler: app.requirePermission('device_groups:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const q = parse(Pagination, req.query);
    await load(id);
    const ids = await groupMemberIds(app.db, id, online);
    if (!ids.length) return { items: [], total: 0 };
    const items = await app.db.select(deviceCols).from(devices).where(inArray(devices.id, ids)).orderBy(asc(devices.hostname)).limit(q.limit).offset(q.offset);
    return { items, total: ids.length };
  });

  app.delete('/device-groups/:id', { preHandler: app.requirePermission('device_groups:delete') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const g = await load(id);
    const [used] = await app.db
      .select({ n: count() })
      .from(jobs)
      .where(sql`${jobs.targets}->'groupIds' @> ${JSON.stringify([id])}::jsonb`);
    if ((used?.n ?? 0) > 0) throw conflict(`Device group is targeted by ${used!.n} job(s)`);
    await app.db.delete(deviceGroups).where(eq(deviceGroups.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'device_group.delete', targetType: 'device_group', targetId: id, details: { name: g.name }, ip: req.ip });
    return reply.code(204).send();
  });
}
