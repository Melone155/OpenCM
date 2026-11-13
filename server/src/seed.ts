import { and, count, eq } from 'drizzle-orm';
import { SYSTEM_ACTOR, writeAudit } from './audit.ts';
import { hashPassword } from './auth/password.ts';
import { SYSTEM_ROLES } from './auth/permissions.ts';
import type { Config } from './config.ts';
import type { Db } from './db/client.ts';
import { roles, userRoles, users } from './db/schema.ts';

/** Idempotent: creates system roles and, if no user exists yet, the bootstrap admin. */
export async function ensureSeed(
  db: Db,
  config: Pick<Config, 'BOOTSTRAP_ADMIN_USER' | 'BOOTSTRAP_ADMIN_PASSWORD'>,
  log: { info: (msg: string) => void; warn: (msg: string) => void },
): Promise<void> {
  for (const r of SYSTEM_ROLES) {
    await db
      .insert(roles)
      .values({ name: r.name, description: r.description, permissions: [...r.permissions], isSystem: true })
      .onConflictDoNothing({ target: roles.name });
    // system roles follow the current catalogue (e.g. Auditor gets read access to new modules)
    await db
      .update(roles)
      .set({ permissions: [...r.permissions], description: r.description })
      .where(and(eq(roles.name, r.name), eq(roles.isSystem, true)));
  }

  const [row] = await db.select({ n: count() }).from(users);
  if ((row?.n ?? 0) > 0) return;

  const { BOOTSTRAP_ADMIN_USER: username, BOOTSTRAP_ADMIN_PASSWORD: password } = config;
  if (!username || !password) {
    log.warn('No users exist and BOOTSTRAP_ADMIN_USER/BOOTSTRAP_ADMIN_PASSWORD are not set – nobody can log in.');
    return;
  }

  const [admin] = await db
    .insert(users)
    .values({ username, displayName: 'Administrator', passwordHash: await hashPassword(password) })
    .returning({ id: users.id });
  const [adminRole] = await db.select({ id: roles.id }).from(roles).where(eq(roles.name, 'Administrator'));
  await db.insert(userRoles).values({ userId: admin!.id, roleId: adminRole!.id });
  await writeAudit(db, SYSTEM_ACTOR, {
    action: 'user.bootstrap',
    targetType: 'user',
    targetId: admin!.id,
    details: { username },
  });
  log.info(`Bootstrap admin "${username}" created.`);
}
