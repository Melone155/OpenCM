import { asc, eq, inArray } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import type { Db } from '../db/client.ts';
import { groupRoles, groups, roles, userGroups, users } from '../db/schema.ts';
import { conflict, HttpError, IdParams, isUniqueViolation, notFound, parse, Uuid } from '../http.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';
import { RoleAssignment, toAssignments, validateAssignments } from './users.ts';

const LdapDn = z.string().trim().min(3).max(1000).nullable();

const CreateGroup = z.object({
  name: z.string().trim().min(1).max(100),
  description: z.string().max(500).default(''),
  roleIds: z.array(Uuid).optional(),
  roleAssignments: z.array(RoleAssignment).max(100).optional(),
  memberIds: z.array(Uuid).default([]),
  ldapGroup: LdapDn.default(null),
});
const UpdateGroup = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  description: z.string().max(500).optional(),
  roleIds: z.array(Uuid).optional(),
  roleAssignments: z.array(RoleAssignment).max(100).optional(),
  memberIds: z.array(Uuid).optional(),
  ldapGroup: LdapDn.optional(),
});

async function loadGroup(db: Db, id: string) {
  const [g] = await db.select().from(groups).where(eq(groups.id, id));
  if (!g) throw notFound('Group');
  const r = await db
    .select({ id: roles.id, name: roles.name, scopeDeviceGroupIds: groupRoles.scopeDeviceGroupIds })
    .from(groupRoles)
    .innerJoin(roles, eq(roles.id, groupRoles.roleId))
    .where(eq(groupRoles.groupId, id));
  const m = await db
    .select({ id: users.id, username: users.username })
    .from(userGroups)
    .innerJoin(users, eq(users.id, userGroups.userId))
    .where(eq(userGroups.groupId, id));
  return { ...g, roles: r, members: m };
}

async function assertUsersExist(db: Db, ids: string[]) {
  if (!ids.length) return;
  const found = await db.select({ id: users.id }).from(users).where(inArray(users.id, ids));
  if (found.length !== new Set(ids).size) throw new HttpError(400, 'invalid_reference', 'Unknown user id');
}

export function groupRoutes(app: FastifyInstance) {
  app.get('/groups', { preHandler: app.requirePermission('groups:read') }, async () => ({
    items: await app.db.select().from(groups).orderBy(asc(groups.name)),
  }));

  app.get('/groups/:id', { preHandler: app.requirePermission('groups:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    return loadGroup(app.db, id);
  });

  app.post('/groups', { preHandler: app.requirePermission('groups:create') }, async (req, reply) => {
    const body = parse(CreateGroup, req.body);
    const assignments = toAssignments(body.roleIds, body.roleAssignments) ?? [];
    // Adding members to a role-bearing group grants them its roles.
    await validateAssignments(app.db, principalOf(req).grants, assignments);
    await assertUsersExist(app.db, body.memberIds);
    let id: string;
    try {
      id = await app.db.transaction(async (tx) => {
        const [g] = await tx.insert(groups).values({ name: body.name, description: body.description, ldapGroup: body.ldapGroup }).returning({ id: groups.id });
        if (assignments.length) await tx.insert(groupRoles).values(assignments.map((a) => ({ groupId: g!.id, ...a })));
        if (body.memberIds.length) await tx.insert(userGroups).values(body.memberIds.map((userId) => ({ groupId: g!.id, userId })));
        return g!.id;
      });
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Group "${body.name}" already exists`);
      throw err;
    }
    await writeAudit(app.db, actorOf(req), { action: 'group.create', targetType: 'group', targetId: id, details: { ...body, roleAssignments: assignments }, ip: req.ip });
    return reply.code(201).send(await loadGroup(app.db, id));
  });

  app.patch('/groups/:id', { preHandler: app.requirePermission('groups:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(UpdateGroup, req.body);
    const existing = await loadGroup(app.db, id);
    const actor = principalOf(req);
    const assignments = toAssignments(body.roleIds, body.roleAssignments);
    // Changing roles, members or the directory mapping effectively assigns the group's roles → escalation check.
    if (assignments || body.memberIds || body.ldapGroup !== undefined) {
      await validateAssignments(
        app.db,
        actor.grants,
        assignments ?? existing.roles.map((r) => ({ roleId: r.id, scopeDeviceGroupIds: r.scopeDeviceGroupIds })),
      );
    }
    if (body.memberIds) await assertUsersExist(app.db, body.memberIds);
    try {
      await app.db.transaction(async (tx) => {
        if (body.name !== undefined || body.description !== undefined || body.ldapGroup !== undefined) {
          await tx
            .update(groups)
            .set({
              ...(body.name !== undefined && { name: body.name }),
              ...(body.description !== undefined && { description: body.description }),
              ...(body.ldapGroup !== undefined && { ldapGroup: body.ldapGroup }),
              updatedAt: new Date(),
            })
            .where(eq(groups.id, id));
        }
        if (assignments) {
          await tx.delete(groupRoles).where(eq(groupRoles.groupId, id));
          if (assignments.length) await tx.insert(groupRoles).values(assignments.map((a) => ({ groupId: id, ...a })));
        }
        if (body.memberIds) {
          await tx.delete(userGroups).where(eq(userGroups.groupId, id));
          if (body.memberIds.length) await tx.insert(userGroups).values(body.memberIds.map((userId) => ({ groupId: id, userId })));
        }
      });
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Group "${body.name}" already exists`);
      throw err;
    }
    await writeAudit(app.db, actorOf(req), { action: 'group.update', targetType: 'group', targetId: id, details: body, ip: req.ip });
    return loadGroup(app.db, id);
  });

  app.delete('/groups/:id', { preHandler: app.requirePermission('groups:delete') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const g = await loadGroup(app.db, id);
    await app.db.delete(groups).where(eq(groups.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'group.delete', targetType: 'group', targetId: id, details: { name: g.name }, ip: req.ip });
    return reply.code(204).send();
  });
}
