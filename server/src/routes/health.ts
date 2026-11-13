import { sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';

export const VERSION = '0.8.0';

export function healthRoutes(app: FastifyInstance) {
  app.get('/health', async (_req, reply) => {
    try {
      await app.db.execute(sql`select 1`);
      return { status: 'ok', version: VERSION, database: 'ok' };
    } catch {
      return reply.code(503).send({ status: 'degraded', version: VERSION, database: 'unreachable' });
    }
  });
}
