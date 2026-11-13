import { eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import { licenses } from '../db/schema.ts';
import { IdParams, notFound, parse } from '../http.ts';
import { licenseDevices, licenseRegexes, licenseState, listLicenses } from '../licenses.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';

const Day = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'YYYY-MM-DD');
const Body = z.object({
  name: z.string().trim().min(1).max(150),
  vendor: z.string().trim().max(150).default(''),
  softwarePattern: z.string().trim().min(1).max(200),
  publisherPattern: z.string().trim().max(200).nullable().default(null),
  seats: z.number().int().min(0).max(10_000_000),
  expiresAt: Day.nullable().default(null),
  cost: z.number().min(0).max(1e10).nullable().default(null),
  notes: z.string().max(4000).default(''),
});
const Patch = z.object({
  name: z.string().trim().min(1).max(150).optional(),
  vendor: z.string().trim().max(150).optional(),
  softwarePattern: z.string().trim().min(1).max(200).optional(),
  publisherPattern: z.string().trim().max(200).nullable().optional(),
  seats: z.number().int().min(0).max(10_000_000).optional(),
  expiresAt: Day.nullable().optional(),
  cost: z.number().min(0).max(1e10).nullable().optional(),
  notes: z.string().max(4000).optional(),
});

export function licenseRoutes(app: FastifyInstance) {
  async function load(id: string) {
    const [l] = await app.db.select().from(licenses).where(eq(licenses.id, id));
    if (!l) throw notFound('License');
    return l;
  }
  const strip = ({ softwareRegex: _s, publisherRegex: _p, overused: _o, ...rest }: typeof licenses.$inferSelect) => rest;

  app.get('/licenses', { preHandler: app.requirePermission('licenses:read') }, async () => ({
    items: (await listLicenses(app.db)).map(({ storedOverused: _s, ...l }) => l),
  }));

  app.post('/licenses', { preHandler: app.requirePermission('licenses:create') }, async (req, reply) => {
    const body = parse(Body, req.body);
    const [l] = await app.db
      .insert(licenses)
      .values({ ...body, cost: body.cost === null ? null : String(body.cost), ...licenseRegexes(body.softwarePattern, body.publisherPattern), createdBy: principalOf(req).userId })
      .returning();
    await writeAudit(app.db, actorOf(req), { action: 'license.create', targetType: 'license', targetId: l!.id, details: { name: body.name, seats: body.seats }, ip: req.ip });
    const devs = await licenseDevices(app.db, l!);
    return reply.code(201).send({ ...strip(l!), ...licenseState(l!, devs.length), devices: devs });
  });

  app.get('/licenses/:id', { preHandler: app.requirePermission('licenses:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const l = await load(id);
    const devs = await licenseDevices(app.db, l);
    return { ...strip(l), ...licenseState(l, devs.length), devices: devs };
  });

  app.patch('/licenses/:id', { preHandler: app.requirePermission('licenses:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const cur = await load(id);
    const body = parse(Patch, req.body);
    const pattern = body.softwarePattern ?? cur.softwarePattern;
    const publisher = body.publisherPattern === undefined ? cur.publisherPattern : body.publisherPattern;
    const { cost, ...rest } = body;
    const [l] = await app.db
      .update(licenses)
      .set({ ...rest, ...(cost !== undefined ? { cost: cost === null ? null : String(cost) } : {}), ...licenseRegexes(pattern, publisher), updatedAt: new Date() })
      .where(eq(licenses.id, id))
      .returning();
    await writeAudit(app.db, actorOf(req), { action: 'license.update', targetType: 'license', targetId: id, details: body, ip: req.ip });
    const devs = await licenseDevices(app.db, l!);
    return { ...strip(l!), ...licenseState(l!, devs.length), devices: devs };
  });

  app.delete('/licenses/:id', { preHandler: app.requirePermission('licenses:delete') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const l = await load(id);
    await app.db.delete(licenses).where(eq(licenses.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'license.delete', targetType: 'license', targetId: id, details: { name: l.name }, ip: req.ip });
    return reply.code(204).send();
  });
}
