import { and, count, desc, eq, gte, lte, type SQL } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { auditLog } from '../db/schema.ts';
import { Pagination, parse, Uuid } from '../http.ts';

const AuditQuery = Pagination.extend({
  action: z.string().max(100).optional(),
  actorId: Uuid.optional(),
  targetType: z.string().max(50).optional(),
  targetId: z.string().max(100).optional(),
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
});

export function auditRoutes(app: FastifyInstance) {
  app.get('/audit-log', { preHandler: app.requirePermission('audit:read') }, async (req) => {
    const q = parse(AuditQuery, req.query);
    const conds: SQL[] = [];
    if (q.action) conds.push(eq(auditLog.action, q.action));
    if (q.actorId) conds.push(eq(auditLog.actorId, q.actorId));
    if (q.targetType) conds.push(eq(auditLog.targetType, q.targetType));
    if (q.targetId) conds.push(eq(auditLog.targetId, q.targetId));
    if (q.from) conds.push(gte(auditLog.at, q.from));
    if (q.to) conds.push(lte(auditLog.at, q.to));
    const where = conds.length ? and(...conds) : undefined;
    const items = await app.db.select().from(auditLog).where(where).orderBy(desc(auditLog.id)).limit(q.limit).offset(q.offset);
    const [total] = await app.db.select({ n: count() }).from(auditLog).where(where);
    return { items, total: total?.n ?? 0 };
  });
}
