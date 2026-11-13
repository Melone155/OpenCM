import { asc, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import { assertCanGrant } from '../auth/escalation.ts';
import { ACTIONS, isValidGrant, MODULES, type Module } from '../auth/permissions.ts';
import { roles } from '../db/schema.ts';
import { conflict, IdParams, isUniqueViolation, notFound, parse } from '../http.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';

const Grant = z.string().refine(isValidGrant, { message: 'unknown permission' });

const CreateRole = z.object({
  name: z.string().trim().min(1).max(100),
  description: z.string().max(500).default(''),
  permissions: z.array(Grant).max(500).default([]),
});
// Explicit (no defaults!): with zod 4, `.partial()` still applies field defaults,
// which would silently reset omitted fields.
const UpdateRole = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  description: z.string().max(500).optional(),
  permissions: z.array(Grant).max(500).optional(),
});

export function roleRoutes(app: FastifyInstance) {
  app.get('/permissions', { preHandler: app.requireAuth }, async () => ({
    actions: ACTIONS,
    modules: (Object.keys(MODULES) as Module[]).map((m) => ({ module: m, label: MODULES[m].label, actions: MODULES[m].actions })),
  }));

  app.get('/roles', { preHandler: app.requirePermission('roles:read') }, async () => ({
    items: await app.db.select().from(roles).orderBy(asc(roles.name)),
  }));

  app.get('/roles/:id', { preHandler: app.requirePermission('roles:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const [r] = await app.db.select().from(roles).where(eq(roles.id, id));
    if (!r) throw notFound('Role');
    return r;
  });

  app.post('/roles', { preHandler: app.requirePermission('roles:create') }, async (req, reply) => {
    const body = parse(CreateRole, req.body);
    assertCanGrant(principalOf(req).grants, body.permissions);
    try {
      const [r] = await app.db.insert(roles).values({ ...body, permissions: [...new Set(body.permissions)] }).returning();
      await writeAudit(app.db, actorOf(req), { action: 'role.create', targetType: 'role', targetId: r!.id, details: body, ip: req.ip });
      return reply.code(201).send(r);
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Role "${body.name}" already exists`);
      throw err;
    }
  });

  app.patch('/roles/:id', { preHandler: app.requirePermission('roles:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(UpdateRole, req.body);
    const [existing] = await app.db.select().from(roles).where(eq(roles.id, id));
    if (!existing) throw notFound('Role');
    if (existing.isSystem) throw conflict('System roles cannot be modified');
    // Changing a role re-grants its permissions to all holders → actor must hold old and new grants.
    if (body.permissions) assertCanGrant(principalOf(req).grants, [...existing.permissions, ...body.permissions]);
    try {
      const [r] = await app.db
        .update(roles)
        .set({ ...body, ...(body.permissions && { permissions: [...new Set(body.permissions)] }), updatedAt: new Date() })
        .where(eq(roles.id, id))
        .returning();
      await writeAudit(app.db, actorOf(req), { action: 'role.update', targetType: 'role', targetId: id, details: body, ip: req.ip });
      return r;
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Role "${body.name}" already exists`);
      throw err;
    }
  });

  app.delete('/roles/:id', { preHandler: app.requirePermission('roles:delete') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const [existing] = await app.db.select().from(roles).where(eq(roles.id, id));
    if (!existing) throw notFound('Role');
    if (existing.isSystem) throw conflict('System roles cannot be deleted');
    await app.db.delete(roles).where(eq(roles.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'role.delete', targetType: 'role', targetId: id, details: { name: existing.name }, ip: req.ip });
    return reply.code(204).send();
  });
}
