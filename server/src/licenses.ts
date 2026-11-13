/**
 * Software license management: compares the licenses an organisation owns for third-party
 * software (e.g. "50 × Office") with the installations found in the inventory.
 * This has nothing to do with OpenCM's own license – OpenCM is MIT-licensed and unrestricted.
 */
import { and, asc, eq, sql } from 'drizzle-orm';
import type { Db } from './db/client.ts';
import { devices, deviceSoftware, licenses } from './db/schema.ts';
import { globToRegex } from './packages/generate.ts';
import { emitEvent } from './webhooks/events.ts';

export const licenseRegexes = (softwarePattern: string, publisherPattern: string | null | undefined) => ({
  softwareRegex: globToRegex(softwarePattern.trim()),
  publisherRegex: publisherPattern?.trim() ? globToRegex(publisherPattern.trim()) : null,
});

/** Number of active devices with matching software (subquery usable in selects). */
export const usedExpr = sql<number>`(
  select count(distinct ds.device_id)::int
  from device_software ds join devices dd on dd.id = ds.device_id
  where dd.status = 'active'
    and ds.name ~* ${licenses.softwareRegex}
    and (${licenses.publisherRegex} is null or ds.publisher ~* ${licenses.publisherRegex})
)`;

export function licenseState(l: { seats: number; expiresAt: string | null }, used: number, today = new Date()) {
  const days = l.expiresAt ? Math.floor((Date.parse(`${l.expiresAt}T00:00:00Z`) - Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate())) / 86_400_000) : null;
  return {
    used,
    available: l.seats - used,
    overused: used > l.seats,
    daysToExpiry: days,
    expired: days !== null && days < 0,
    expiringSoon: days !== null && days >= 0 && days <= 30,
  };
}

export async function listLicenses(db: Db, today = new Date()) {
  const rows = await db.select({ l: licenses, used: usedExpr }).from(licenses).orderBy(asc(licenses.name));
  return rows.map(({ l, used }) => {
    const { overused: storedOverused, softwareRegex: _s, publisherRegex: _p, ...rest } = l;
    return { ...rest, ...licenseState(l, used, today), storedOverused };
  });
}

/** Devices that use a license. */
export async function licenseDevices(db: Db, l: typeof licenses.$inferSelect) {
  return db
    .selectDistinctOn([devices.id], { deviceId: devices.id, hostname: devices.hostname, software: deviceSoftware.name, version: deviceSoftware.version, publisher: deviceSoftware.publisher })
    .from(deviceSoftware)
    .innerJoin(devices, eq(devices.id, deviceSoftware.deviceId))
    .where(
      and(
        eq(devices.status, 'active'),
        sql`${deviceSoftware.name} ~* ${l.softwareRegex}`,
        l.publisherRegex ? sql`${deviceSoftware.publisher} ~* ${l.publisherRegex}` : undefined,
      ),
    )
    .orderBy(devices.id, asc(deviceSoftware.name));
}

/** Stores the overuse flag and emits license.overused on the transition to overused. */
export async function evaluateLicenses(db: Db): Promise<{ overused: number; newlyOverused: number }> {
  const list = await listLicenses(db);
  let newly = 0;
  for (const l of list) {
    if (l.overused === l.storedOverused) continue;
    await db.update(licenses).set({ overused: l.overused }).where(eq(licenses.id, l.id));
    if (l.overused) {
      newly++;
      await emitEvent(db, 'license.overused', { licenseId: l.id, name: l.name, seats: l.seats, used: l.used });
    }
  }
  return { overused: list.filter((l) => l.overused).length, newlyOverused: newly };
}
