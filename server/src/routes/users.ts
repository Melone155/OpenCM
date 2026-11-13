import { and, count, eq, ilike, inArray, ne, or, type SQL } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import { assertCanAssignGroups, assertCanAssignRoles, assertCanManageUser } from '../auth/escalation.ts';
import { hashPassword, PASSWORD_MIN_LENGTH } from '../auth/password.ts';
import type { Db } from '../db/client.ts';
import { deviceGroups, groups, roles, sessions, userGroups, userRoles, users } from '../db/schema.ts';
import { conflict, HttpError, IdParams, isUniqueViolation, notFound, Pagination, parse, Uuid } from '../http.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';

const Password = z.string().min(PASSWORD_MIN_LENGTH).max(1000);

/** Role assignment, optionally restricted to device groups (null = global). */
export const RoleAssignment = z.object({ roleId: Uuid, scopeDeviceGroupIds: z.array(Uuid).max(200).nullable().default(null) });
export type RoleAssignmentInput = z.infer<typeof RoleAssignment>;

const CreateUser = z.object({
  username: z.string().trim().min(1).max(100).regex(/^[A-Za-z0-9._@-]+$/, 'invalid characters'),
  displayName: z.string().max(200).default(''),
  email: z.string().email().nullable().optional(),
  password: Password,
  isActive: z.boolean().default(true),
  roleIds: z.array(Uuid).optional(),
  roleAssignments: z.array(RoleAssignment).max(100).optional(),
  groupIds: z.array(Uuid).default([]),
});

const UpdateUser = z.object({
  displayName: z.string().max(200).optional(),
  email: z.string().email().nullable().optional(),
  password: Password.optional(),
  isActive: z.boolean().optional(),
  roleIds: z.array(Uuid).optional(),
  roleAssignments: z.array(RoleAssignment).max(100).optional(),
  groupIds: z.array(Uuid).optional(),
});

const ListQuery = Pagination.extend({ search: z.string().max(200).optional() });

const userColumns = {
  id: users.id,
  username: users.username,
  displayName: users.displayName,
  email: users.email,
  authSource: users.authSource,
  isActive: users.isActive,
  mfaEnabled: users.mfaEnabled,
  lastLoginAt: users.lastLoginAt,
  createdAt: users.createdAt,
  updatedAt: users.updatedAt,
};

/** roleIds (legacy, global) or roleAssignments (with scope) → assignments. */
export function toAssignments(roleIds: string[] | undefined, assignments: RoleAssignmentInput[] | undefined): RoleAssignmentInput[] | undefined {
  if (assignments) return assignments;
  return roleIds?.map((roleId) => ({ roleId, scopeDeviceGroupIds: null }));
}

/** Validates assignments: roles exist, actor may grant them, scope groups exist. */
export async function validateAssignments(db: Db, actorGrants: string[], a: RoleAssignmentInput[]): Promise<void> {
  if (new Set(a.map((x) => x.roleId)).size !== a.length) throw new HttpError(400, 'validation_error', 'A role may only be assigned once');
  await assertCanAssignRoles(db, actorGrants, a.map((x) => x.roleId));
  const scopeIds = [...new Set(a.flatMap((x) => x.scopeDeviceGroupIds ?? []))];
  if (scopeIds.length) {
    const found = await db.select({ id: deviceGroups.id }).from(deviceGroups).where(inArray(deviceGroups.id, scopeIds));
    if (found.length !== scopeIds.length) throw new HttpError(400, 'invalid_reference', 'Unknown device group in scope');
  }
  if (a.some((x) => x.scopeDeviceGroupIds && !x.scopeDeviceGroupIds.length)) throw new HttpError(400, 'validation_error', 'A scope needs at least one device group (null = global)');
}

async function loadUser(db: Db, id: string) {
  const [u] = await db.select(userColumns).from(users).where(eq(users.id, id));
  if (!u) throw notFound('User');
  const r = await db
    .select({ id: roles.id, name: roles.name, scopeDeviceGroupIds: userRoles.scopeDeviceGroupIds })
    .from(userRoles)
    .innerJoin(roles, eq(roles.id, userRoles.roleId))
    .where(eq(userRoles.userId, id));
  const g = await db
    .select({ id: groups.id, name: groups.name })
    .from(userGroups)
    .innerJoin(groups, eq(groups.id, userGroups.groupId))
    .where(eq(userGroups.userId, id));
  return { ...u, roles: r, groups: g };
}

async function assertGroupsExist(db: Db, ids: string[]) {
  if (!ids.length) return;
  const found = await db.select({ id: groups.id }).from(groups).where(inArray(groups.id, ids));
  if (found.length !== new Set(ids).size) throw new HttpError(400, 'invalid_reference', 'Unknown group id');
}

export function userRoutes(app: FastifyInstance) {
  app.get('/users', { preHandler: app.requirePermission('users:read') }, async (req) => {
    const q = parse(ListQuery, req.query);
    const where: SQL | undefined = q.search
      ? or(ilike(users.username, `%${q.search}%`), ilike(users.displayName, `%${q.search}%`))
      : undefined;
    const items = await app.db.select(userColumns).from(users).where(where).orderBy(users.username).limit(q.limit).offset(q.offset);
    const [total] = await app.db.select({ n: count() }).from(users).where(where);
    return { items, total: total?.n ?? 0 };
  });

  app.post('/users', { preHandler: app.requirePermission('users:create') }, async (req, reply) => {
    const body = parse(CreateUser, req.body);
    const actor = principalOf(req);
    const assignments = toAssignments(body.roleIds, body.roleAssignments) ?? [];
    await validateAssignments(app.db, actor.grants, assignments);
    await assertGroupsExist(app.db, body.groupIds);
    await assertCanAssignGroups(app.db, actor.grants, body.groupIds);

    const passwordHash = await hashPassword(body.password);
    let id: string;
    try {
      id = await app.db.transaction(async (tx) => {
        const [u] = await tx
          .insert(users)
          .values({ username: body.username, displayName: body.displayName, email: body.email ?? null, passwordHash, isActive: body.isActive })
          .returning({ id: users.id });
        if (assignments.length) await tx.insert(userRoles).values(assignments.map((a) => ({ userId: u!.id, ...a })));
        if (body.groupIds.length) await tx.insert(userGroups).values(body.groupIds.map((groupId) => ({ userId: u!.id, groupId })));
        return u!.id;
      });
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Username "${body.username}" already exists`);
      throw err;
    }
    await writeAudit(app.db, actorOf(req), {
      action: 'user.create',
      targetType: 'user',
      targetId: id,
      details: { username: body.username, roleAssignments: assignments, groupIds: body.groupIds },
      ip: req.ip,
    });
    return reply.code(201).send(await loadUser(app.db, id));
  });

  app.get('/users/:id', { preHandler: app.requirePermission('users:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    return loadUser(app.db, id);
  });

  app.patch('/users/:id', { preHandler: app.requirePermission('users:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(UpdateUser, req.body);
    const actor = principalOf(req);
    const target = await loadUser(app.db, id);
    const assignments = toAssignments(body.roleIds, body.roleAssignments);

    if (id === actor.userId && body.isActive === false) throw conflict('You cannot deactivate yourself');
    if (id === actor.userId && assignments) throw conflict('You cannot change your own roles');
    if (body.password && target.authSource !== 'local') throw conflict('Directory users have no local password');
    if (assignments) await validateAssignments(app.db, actor.grants, assignments);
    if (body.groupIds) {
      await assertGroupsExist(app.db, body.groupIds);
      // only newly added memberships hand out roles; removing a user from a group is always allowed
      const current = new Set(target.groups.map((g) => g.id));
      await assertCanAssignGroups(app.db, actor.grants, body.groupIds.filter((g) => !current.has(g)));
    }
    // Password or activation status of someone else = control over that account (REV-001).
    if (id !== actor.userId && (body.password !== undefined || body.isActive !== undefined)) await assertCanManageUser(app.db, actor.grants, id);

    const passwordHash = body.password ? await hashPassword(body.password) : undefined;
    await app.db.transaction(async (tx) => {
      await tx
        .update(users)
        .set({
          ...(body.displayName !== undefined && { displayName: body.displayName }),
          ...(body.email !== undefined && { email: body.email }),
          ...(body.isActive !== undefined && { isActive: body.isActive }),
          ...(passwordHash && { passwordHash }),
          updatedAt: new Date(),
        })
        .where(eq(users.id, id));
      if (assignments) {
        await tx.delete(userRoles).where(eq(userRoles.userId, id));
        if (assignments.length) await tx.insert(userRoles).values(assignments.map((a) => ({ userId: id, ...a })));
      }
      if (body.groupIds) {
        await tx.delete(userGroups).where(eq(userGroups.userId, id));
        if (body.groupIds.length) await tx.insert(userGroups).values(body.groupIds.map((groupId) => ({ userId: id, groupId })));
      }
      // Deactivation or a password reset by someone else ends all sessions of that user.
      if (body.isActive === false || (passwordHash && id !== actor.userId)) {
        await tx.delete(sessions).where(eq(sessions.userId, id));
      } else if (passwordHash) {
        // own password change: keep the current session (if any), end all others
        await tx.delete(sessions).where(actor.sessionId ? and(eq(sessions.userId, id), ne(sessions.id, actor.sessionId)) : eq(sessions.userId, id));
      }
    });

    const { password: _pw, ...auditDetails } = body;
    await writeAudit(app.db, actorOf(req), {
      action: 'user.update',
      targetType: 'user',
      targetId: id,
      details: { ...auditDetails, passwordChanged: !!passwordHash },
      ip: req.ip,
    });
    return loadUser(app.db, id);
  });

  app.delete('/users/:id', { preHandler: app.requirePermission('users:delete') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    if (id === principalOf(req).userId) throw conflict('You cannot delete yourself');
    const u = await loadUser(app.db, id);
    await assertCanManageUser(app.db, principalOf(req).grants, id);
    await app.db.delete(users).where(eq(users.id, id));
    await writeAudit(app.db, actorOf(req), {
      action: 'user.delete',
      targetType: 'user',
      targetId: id,
      details: { username: u.username },
      ip: req.ip,
    });
    return reply.code(204).send();
  });
}
