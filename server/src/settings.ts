import { eq } from 'drizzle-orm';
import { z } from 'zod';
import type { Config } from './config.ts';
import type { Db } from './db/client.ts';
import { settings } from './db/schema.ts';

export const SecuritySettingsSchema = z.object({
  mfaRequired: z.boolean(),
});
export type SecuritySettings = z.infer<typeof SecuritySettingsSchema>;

export const SecurityPatchSchema = z.object({
  mfaRequired: z.boolean().optional(),
});

export function defaultSecurity(c: Config): SecuritySettings {
  return { mfaRequired: c.MFA_REQUIRED };
}

/** Stored settings override the .env defaults. */
export async function getSecurity(db: Db, c: Config): Promise<SecuritySettings> {
  const [row] = await db.select().from(settings).where(eq(settings.key, 'security'));
  const d = defaultSecurity(c);
  if (!row) return d;
  const v = row.value as Partial<SecuritySettings>;
  return SecuritySettingsSchema.parse({ mfaRequired: v.mfaRequired ?? d.mfaRequired });
}

export async function patchSecurity(db: Db, c: Config, patch: z.infer<typeof SecurityPatchSchema>, userId: string): Promise<SecuritySettings> {
  const cur = await getSecurity(db, c);
  const next = SecuritySettingsSchema.parse({ mfaRequired: patch.mfaRequired ?? cur.mfaRequired });
  await db
    .insert(settings)
    .values({ key: 'security', value: next, updatedBy: userId, updatedAt: new Date() })
    .onConflictDoUpdate({ target: settings.key, set: { value: next, updatedBy: userId, updatedAt: new Date() } });
  return next;
}
