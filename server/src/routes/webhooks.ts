import { randomBytes } from 'node:crypto';
import { and, desc, eq } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import type { SecretBox } from '../auth/secretbox.ts';
import type { Config } from '../config.ts';
import { webhookDeliveries, webhooks } from '../db/schema.ts';
import { conflict, IdParams, notFound, Pagination, parse } from '../http.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';
import { claimDelivery, defaultDeliverDeps, deliverOne, validateWebhookUrl, type DeliverDeps } from '../webhooks/deliver.ts';
import { EVENT_NAMES, EVENTS } from '../webhooks/events.ts';

const Events = z.array(z.enum(['*', ...EVENT_NAMES])).min(1).max(50);
const Secret = z.string().min(16).max(200);
const Body = z.object({
  name: z.string().trim().min(1).max(100),
  url: z.string().max(2000),
  events: Events,
  enabled: z.boolean().default(true),
  secret: Secret.optional(),
});
const Patch = z.object({
  name: z.string().trim().min(1).max(100).optional(),
  url: z.string().max(2000).optional(),
  events: Events.optional(),
  enabled: z.boolean().optional(),
  rotateSecret: z.boolean().optional(),
  secret: Secret.optional(),
});
const DeliveryQuery = Pagination.extend({ status: z.enum(['pending', 'succeeded', 'failed']).optional() });

const out = ({ secretEnc: _s, ...h }: typeof webhooks.$inferSelect) => h;

export function webhookRoutes(app: FastifyInstance, config: Config, secretBox: SecretBox, deps: DeliverDeps = defaultDeliverDeps) {
  async function load(id: string) {
    const [h] = await app.db.select().from(webhooks).where(eq(webhooks.id, id));
    if (!h) throw notFound('Webhook');
    return h;
  }

  app.get('/webhook-events', { preHandler: app.requirePermission('webhooks:read') }, async () => ({
    items: EVENT_NAMES.map((name) => ({ name, label: EVENTS[name] })),
  }));

  app.get('/webhooks', { preHandler: app.requirePermission('webhooks:read') }, async () => {
    const rows = await app.db.select().from(webhooks).orderBy(webhooks.name);
    const last = await Promise.all(
      rows.map(async (h) => (await app.db.select().from(webhookDeliveries).where(eq(webhookDeliveries.webhookId, h.id)).orderBy(desc(webhookDeliveries.createdAt)).limit(1))[0] ?? null),
    );
    return { items: rows.map((h, i) => ({ ...out(h), lastDelivery: last[i] ? { status: last[i]!.status, event: last[i]!.event, responseStatus: last[i]!.responseStatus, lastError: last[i]!.lastError, createdAt: last[i]!.createdAt } : null })) };
  });

  app.post('/webhooks', { preHandler: app.requirePermission('webhooks:create') }, async (req, reply) => {
    const body = parse(Body, req.body);
    validateWebhookUrl(body.url, config.WEBHOOK_ALLOW_HTTP);
    const secret = body.secret ?? randomBytes(24).toString('base64url');
    const [h] = await app.db
      .insert(webhooks)
      .values({ name: body.name, url: body.url, events: body.events, enabled: body.enabled, secretEnc: secretBox.seal(secret), createdBy: principalOf(req).userId })
      .returning();
    await writeAudit(app.db, actorOf(req), { action: 'webhook.create', targetType: 'webhook', targetId: h!.id, details: { name: body.name, url: body.url, events: body.events }, ip: req.ip });
    // the secret is shown exactly once
    return reply.code(201).send({ ...out(h!), secret });
  });

  app.patch('/webhooks/:id', { preHandler: app.requirePermission('webhooks:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const body = parse(Patch, req.body);
    await load(id);
    if (body.url) validateWebhookUrl(body.url, config.WEBHOOK_ALLOW_HTTP);
    const secret = body.secret ?? (body.rotateSecret ? randomBytes(24).toString('base64url') : null);
    const { rotateSecret: _r, secret: _s, ...rest } = body;
    const [h] = await app.db
      .update(webhooks)
      .set({ ...rest, ...(secret ? { secretEnc: secretBox.seal(secret) } : {}), updatedAt: new Date() })
      .where(eq(webhooks.id, id))
      .returning();
    await writeAudit(app.db, actorOf(req), { action: 'webhook.update', targetType: 'webhook', targetId: id, details: { fields: Object.keys(rest), secretRotated: !!secret }, ip: req.ip });
    return { ...out(h!), ...(secret ? { secret } : {}) };
  });

  app.delete('/webhooks/:id', { preHandler: app.requirePermission('webhooks:delete') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const h = await load(id);
    await app.db.delete(webhooks).where(eq(webhooks.id, id));
    await writeAudit(app.db, actorOf(req), { action: 'webhook.delete', targetType: 'webhook', targetId: id, details: { name: h.name }, ip: req.ip });
    return reply.code(204).send();
  });

  app.post('/webhooks/:id/test', { preHandler: app.requirePermission('webhooks:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const h = await load(id);
    const now = deps.now();
    const [d] = await app.db
      .insert(webhookDeliveries)
      .values({ webhookId: id, event: 'webhook.test', payload: { event: 'webhook.test', occurredAt: now.toISOString(), data: { message: 'OpenCM Testnachricht', webhook: h.name } }, nextAttemptAt: now })
      .returning();
    const claimed = await claimDelivery(app.db, d!, now);
    return deliverOne(app.db, config, secretBox, deps, claimed!, h);
  });

  app.get('/webhooks/:id/deliveries', { preHandler: app.requirePermission('webhooks:read') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const q = parse(DeliveryQuery, req.query);
    await load(id);
    const rows = await app.db
      .select()
      .from(webhookDeliveries)
      .where(and(eq(webhookDeliveries.webhookId, id), q.status ? eq(webhookDeliveries.status, q.status) : undefined))
      .orderBy(desc(webhookDeliveries.createdAt))
      .limit(q.limit)
      .offset(q.offset);
    return { items: rows };
  });

  app.post('/webhook-deliveries/:id/redeliver', { preHandler: app.requirePermission('webhooks:update') }, async (req) => {
    const { id } = parse(IdParams, req.params);
    const [d] = await app.db.select().from(webhookDeliveries).where(eq(webhookDeliveries.id, id));
    if (!d) throw notFound('Delivery');
    if (d.status === 'pending') throw conflict('Delivery is still pending');
    const [u] = await app.db.update(webhookDeliveries).set({ status: 'pending', attempts: 0, nextAttemptAt: new Date(), lastError: null }).where(eq(webhookDeliveries.id, id)).returning();
    await writeAudit(app.db, actorOf(req), { action: 'webhook.redeliver', targetType: 'webhook', targetId: d.webhookId, details: { deliveryId: id, event: d.event }, ip: req.ip });
    return u;
  });
}
