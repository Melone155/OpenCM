import { and, asc, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import { customFields, deviceCustomValues, devices } from '../db/schema.ts';
import { conflict, HttpError, IdParams, isUniqueViolation, notFound, parse, Uuid } from '../http.ts';
import { assertInScope } from '../auth/scope.ts';
import { actorOf } from '../plugins/auth.ts';

const FieldType = z.enum(['string', 'number', 'boolean', 'date']);
const CreateField = z.object({
  name: z.string().regex(/^[a-z][a-z0-9_]{0,62}$/, 'lowercase letters, digits, underscore'),
  label: z.string().trim().min(1).max(100),
  type: FieldType.default('string'),
  description: z.string().max(500).default(''),
});
const UpdateField = z.object({ label: z.string().trim().min(1).max(100).optional(), description: z.string().max(500).optional() });
const DeviceFieldParams = z.object({ id: Uuid, fieldId: Uuid });
const SetValue = z.object({ value: z.union([z.string().max(1000), z.number(), z.boolean()]) });

export function validateCustomValue(type: string, v: string | number | boolean): string {
  switch (type) {
    case 'number':
      if (typeof v === 'number' && Number.isFinite(v)) return String(v);
      if (typeof v === 'string' && /^-?\d+(\.\d+)?$/.test(v.trim())) return v.trim();
      break;
    case 'boolean':
      if (typeof v === 'boolean') return String(v);
      if (v === 'true' || v === 'false') return v;
      break;
    case 'date':
      if (typeof v === 'string' && !Number.isNaN(Date.parse(v))) return new Date(v).toISOString();
      break;
    default:
      return String(v);
  }
  throw new HttpError(400, 'validation_error', `Value is not a valid ${type}`);
}

export function customFieldRoutes(app: FastifyInstance) {
  app.get('/custom-fields', { preHandler: app.requirePermission('inventory:read') }, async () => ({
    items: await app.db.select().from(customFields).orderBy(asc(customFields.label)),
  }));

  app.post('/custom-fields', { preHandler: app.requirePermission('settings:update') }, async (req, reply) => {
    const body = parse(CreateField, req.body);
    try {
      const [f] = await app.db.insert(customFields).values(body).returning();
      await writeAudit(app.db, actorOf(req), { action: 'custom_field.create', targetType: 'custom_field', targetId: f!.id, details: body, ip: req.ip });
      return reply.code(201).send(f);
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict(`Custom field "${body.name}" already exists`);
      throw err;
    }
  });

  app.patch('/custom-fields/:id', { preHandler: app.requirePermission('settings:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(UpdateField, req.body);
    const [f] = await app.db.update(customFields).set(body).where(eq(customFields.id, id)).returning();
    if (!f) throw notFound('Custom field');
    await writeAudit(app.db, actorOf(req), { action: 'custom_field.update', targetType: 'custom_field', targetId: id, details: body, ip: req.ip });
    return f;
  });

  app.delete('/custom-fields/:id', { preHandler: app.requirePermission('settings:update') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const [f] = await app.db.delete(customFields).where(eq(customFields.id, id)).returning();
    if (!f) throw notFound('Custom field');
    await writeAudit(app.db, actorOf(req), { action: 'custom_field.delete', targetType: 'custom_field', targetId: id, details: { name: f.name }, ip: req.ip });
    return reply.code(204).send();
  });

  app.get('/devices/:id/custom-fields', { preHandler: app.requireScopedPermission('inventory:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    assertInScope(await app.deviceScope(req, 'inventory:read'), id);
    const [d] = await app.db.select({ id: devices.id }).from(devices).where(eq(devices.id, id));
    if (!d) throw notFound('Device');
    const fields = await app.db.select().from(customFields).orderBy(asc(customFields.label));
    const values = await app.db.select().from(deviceCustomValues).where(eq(deviceCustomValues.deviceId, id));
    return {
      items: fields.map((f) => {
        const v = values.find((x) => x.fieldId === f.id);
        return { fieldId: f.id, name: f.name, label: f.label, type: f.type, value: v?.value ?? null, source: v?.source ?? null, updatedAt: v?.updatedAt ?? null };
      }),
    };
  });

  app.put('/devices/:id/custom-fields/:fieldId', { preHandler: app.requireScopedPermission('inventory:update') }, async (req) => {
    const { id, fieldId } = parse(DeviceFieldParams, req.params);
    assertInScope(await app.deviceScope(req, 'inventory:update'), id);
    const { value } = parse(SetValue, req.body);
    const [d] = await app.db.select({ id: devices.id }).from(devices).where(eq(devices.id, id));
    const [f] = await app.db.select().from(customFields).where(eq(customFields.id, fieldId));
    if (!d) throw notFound('Device');
    if (!f) throw notFound('Custom field');
    const v = validateCustomValue(f.type, value);
    const now = new Date();
    await app.db
      .insert(deviceCustomValues)
      .values({ deviceId: id, fieldId, value: v, source: 'manual', updatedAt: now })
      .onConflictDoUpdate({ target: [deviceCustomValues.deviceId, deviceCustomValues.fieldId], set: { value: v, source: 'manual', updatedAt: now } });
    await writeAudit(app.db, actorOf(req), { action: 'device.custom_field_set', targetType: 'device', targetId: id, details: { field: f.name, value: v }, ip: req.ip });
    return { fieldId, name: f.name, label: f.label, type: f.type, value: v, source: 'manual', updatedAt: now };
  });

  app.delete('/devices/:id/custom-fields/:fieldId', { preHandler: app.requireScopedPermission('inventory:update') }, async (req, reply) => {
    const { id, fieldId } = parse(DeviceFieldParams, req.params);
    assertInScope(await app.deviceScope(req, 'inventory:update'), id);
    await app.db.delete(deviceCustomValues).where(and(eq(deviceCustomValues.deviceId, id), eq(deviceCustomValues.fieldId, fieldId)));
    await writeAudit(app.db, actorOf(req), { action: 'device.custom_field_clear', targetType: 'device', targetId: id, details: { fieldId }, ip: req.ip });
    return reply.code(204).send();
  });
}
