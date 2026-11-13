import type { Db } from './db/client.ts';
import { auditLog } from './db/schema.ts';

export interface AuditActor {
  type: 'user' | 'api_token' | 'agent' | 'system';
  id: string | null;
  name: string;
}

export interface AuditEntry {
  action: string;
  targetType?: string;
  targetId?: string;
  details?: Record<string, unknown>;
  ip?: string | null;
}

export const SYSTEM_ACTOR: AuditActor = { type: 'system', id: null, name: 'system' };

export async function writeAudit(db: Db, actor: AuditActor, entry: AuditEntry): Promise<void> {
  await db.insert(auditLog).values({
    actorType: actor.type,
    actorId: actor.id,
    actorName: actor.name,
    action: entry.action,
    targetType: entry.targetType ?? null,
    targetId: entry.targetId ?? null,
    details: entry.details ?? {},
    ip: entry.ip ?? null,
  });
}
