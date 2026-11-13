import { lt } from 'drizzle-orm';
import type { Db } from './db/client.ts';
import { sessions } from './db/schema.ts';

/** Removes expired sessions. Returns the number of deleted rows. */
export async function purgeExpiredSessions(db: Db, now = new Date()): Promise<number> {
  const deleted = await db.delete(sessions).where(lt(sessions.expiresAt, now)).returning({ id: sessions.id });
  return deleted.length;
}
