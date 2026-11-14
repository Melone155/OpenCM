/**
 * Event outbox. emitEvent() only writes rows into webhook_deliveries for subscribed,
 * enabled webhooks – the worker delivers them (deliver.ts). It never throws: a broken
 * webhook configuration must not break the action that caused the event.
 */
import { and, arrayOverlaps, eq } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { webhookDeliveries, webhooks } from '../db/schema.ts';

export const EVENTS = {
  'device.enrolled': 'Gerät registriert',
  'run.completed': 'Ausführung abgeschlossen',
  'task.failed': 'Task fehlgeschlagen (endgültig)',
  'deployment.completed': 'Verteilung abgeschlossen',
  'deployment.paused': 'Verteilung angehalten (Erfolgsquote/Fehler)',
  'vulnerability.findings.new': 'Neue kritische / aktiv ausgenutzte Schwachstellen',
  'patch.scan_failed': 'Patch-Scan fehlgeschlagen',
  'security.integrity_violation': 'Hash-Prüfung fehlgeschlagen (Manipulationsverdacht)',
  'license.overused': 'Softwarelizenz überschritten (mehr Installationen als Lizenzen)',
  'device.security_changed': 'Sicherheitsstatus verschlechtert (z. B. BitLocker oder Virenschutz aus)',
  'webhook.test': 'Testnachricht',
} as const;

export type EventName = keyof typeof EVENTS;
export const EVENT_NAMES = Object.keys(EVENTS) as EventName[];

export async function emitEvent(db: Db, event: EventName, data: Record<string, unknown>, now = new Date()): Promise<number> {
  try {
    const subs = await db
      .select({ id: webhooks.id })
      .from(webhooks)
      .where(and(eq(webhooks.enabled, true), arrayOverlaps(webhooks.events, [event, '*'])));
    if (!subs.length) return 0;
    const payload = { event, occurredAt: now.toISOString(), data };
    await db.insert(webhookDeliveries).values(subs.map((s) => ({ webhookId: s.id, event, payload, nextAttemptAt: now })));
    return subs.length;
  } catch {
    return 0;
  }
}
