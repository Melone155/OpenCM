import { eq, sql } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { deviceHistory, deviceInventory, devices, deviceSoftware } from '../db/schema.ts';
import { emitSecurityChanged, storePosture } from '../security/posture.ts';
import { diffInventories } from './diff.ts';
import { InventorySchema, type Inventory } from './schema.ts';

const CHUNK = 1000;

const jsonb = (v: unknown) => sql`${JSON.stringify(v ?? null)}::jsonb`;
const MAX_HISTORY_PER_INGEST = 5000;

export interface IngestOptions {
  /** antivirus signatures older than this count as outdated (SECURITY_AV_MAX_AGE_DAYS) */
  maxSignatureAgeDays?: number;
}

/** Stores a new inventory snapshot, replaces the software list, records changes and the security posture. */
export async function ingestInventory(db: Db, deviceId: string, inv: Inventory, opts: IngestOptions = {}): Promise<{ changes: number }> {
  let securityEvent: Record<string, unknown> | null = null;
  const result = await db.transaction(async (tx) => {
    const [prevRow] = await tx.select().from(deviceInventory).where(eq(deviceInventory.deviceId, deviceId));
    const { software, ...snapshot } = inv;

    let changes = 0;
    if (prevRow) {
      const prevSoftware = await tx
        .select({
          name: deviceSoftware.name,
          version: deviceSoftware.version,
          publisher: deviceSoftware.publisher,
          installDate: deviceSoftware.installDate,
          source: deviceSoftware.source,
          arch: deviceSoftware.arch,
        })
        .from(deviceSoftware)
        .where(eq(deviceSoftware.deviceId, deviceId));
      const prev = InventorySchema.parse({ ...prevRow.data, software: prevSoftware });
      const diff = diffInventories(prev, inv).slice(0, MAX_HISTORY_PER_INGEST);
      changes = diff.length;
      for (let i = 0; i < diff.length; i += CHUNK) {
        await tx.insert(deviceHistory).values(
          diff.slice(i, i + CHUNK).map((d) => ({
            deviceId,
            category: d.category,
            change: d.change,
            itemKey: d.itemKey,
            // explicit serialisation: drivers disagree on how a bare JS string maps to jsonb
            oldValue: jsonb(d.oldValue),
            newValue: jsonb(d.newValue),
          })),
        );
      }
    } else {
      await tx.insert(deviceHistory).values({
        deviceId,
        category: 'device',
        change: 'added',
        itemKey: 'initial inventory',
        oldValue: null,
        newValue: { software: software.length, services: inv.services.length },
      });
    }

    const data = { ...snapshot, collectedAt: inv.collectedAt.toISOString() } as Record<string, unknown>;
    await tx
      .insert(deviceInventory)
      .values({ deviceId, collectedAt: inv.collectedAt, data })
      .onConflictDoUpdate({ target: deviceInventory.deviceId, set: { collectedAt: inv.collectedAt, receivedAt: new Date(), data } });

    await tx.delete(deviceSoftware).where(eq(deviceSoftware.deviceId, deviceId));
    for (let i = 0; i < software.length; i += CHUNK) {
      await tx.insert(deviceSoftware).values(software.slice(i, i + CHUNK).map((s) => ({ deviceId, ...s })));
    }

    const [dev] = await tx
      .update(devices)
      .set({
        inventoryRequested: false,
        lastInventoryAt: new Date(),
        manufacturer: inv.hardware.manufacturer,
        model: inv.hardware.model,
        serialNumber: inv.hardware.serialNumber,
        ...(inv.os.name && { osVersion: [inv.os.name, inv.os.version].filter(Boolean).join(' ') }),
        ...(inv.loggedOnUsers.length && { loggedOnUser: inv.loggedOnUsers.join(', ') }),
        updatedAt: new Date(),
      })
      .where(eq(devices.id, deviceId))
      .returning({ os: devices.os, hostname: devices.hostname });

    if (inv.security && dev) {
      const r = await storePosture(tx, deviceId, dev.os, dev.hostname, inv.security, inv.collectedAt, { maxSignatureAgeDays: opts.maxSignatureAgeDays ?? 3 });
      securityEvent = r.event;
    }
    return { changes };
  });
  await emitSecurityChanged(db, securityEvent);
  return result;
}
