import { eq } from 'drizzle-orm';
import { z } from 'zod';
import type { Config } from './config.ts';
import type { Db } from './db/client.ts';
import { settings } from './db/schema.ts';

export const SecuritySettingsSchema = z.object({
  mfaRequired: z.boolean(),
  fourEyes: z.object({
    enabled: z.boolean(),
    /** mass executions on >= this many devices need a second person (0 = only "all devices") */
    deviceThreshold: z.number().int().min(0).max(1_000_000),
  }),
});
export type SecuritySettings = z.infer<typeof SecuritySettingsSchema>;

export const SecurityPatchSchema = z.object({
  mfaRequired: z.boolean().optional(),
  fourEyes: z.object({ enabled: z.boolean().optional(), deviceThreshold: z.number().int().min(0).max(1_000_000).optional() }).optional(),
});

export function defaultSecurity(c: Config): SecuritySettings {
  return { mfaRequired: c.MFA_REQUIRED, fourEyes: { enabled: c.FOUR_EYES_ENABLED, deviceThreshold: c.FOUR_EYES_DEVICE_THRESHOLD } };
}

/** Stored settings override the .env defaults. */
export async function getSecurity(db: Db, c: Config): Promise<SecuritySettings> {
  const [row] = await db.select().from(settings).where(eq(settings.key, 'security'));
  const d = defaultSecurity(c);
  if (!row) return d;
  const v = row.value as Partial<SecuritySettings>;
  return SecuritySettingsSchema.parse({ mfaRequired: v.mfaRequired ?? d.mfaRequired, fourEyes: { ...d.fourEyes, ...(v.fourEyes ?? {}) } });
}

export async function patchSecurity(db: Db, c: Config, patch: z.infer<typeof SecurityPatchSchema>, userId: string): Promise<SecuritySettings> {
  const cur = await getSecurity(db, c);
  const next = SecuritySettingsSchema.parse({
    mfaRequired: patch.mfaRequired ?? cur.mfaRequired,
    fourEyes: { ...cur.fourEyes, ...(patch.fourEyes ?? {}) },
  });
  await db
    .insert(settings)
    .values({ key: 'security', value: next, updatedBy: userId, updatedAt: new Date() })
    .onConflictDoUpdate({ target: settings.key, set: { value: next, updatedBy: userId, updatedAt: new Date() } });
  return next;
}

/** Does a mass execution need four-eyes approval? */
export function needsApproval(s: SecuritySettings, target: { deviceCount: number; allDevices: boolean }): boolean {
  if (!s.fourEyes.enabled) return false;
  if (target.allDevices) return true;
  return s.fourEyes.deviceThreshold > 0 && target.deviceCount >= s.fourEyes.deviceThreshold;
}
