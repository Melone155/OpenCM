import { eq, inArray } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { groupRoles, roles, userGroups, userRoles } from '../db/schema.ts';
import { ALL_PERMISSIONS, hasPermission } from './permissions.ts';

/** Grants that only apply to devices in the given device groups. */
export interface ScopedGrant {
  grants: string[];
  deviceGroupIds: string[];
}

export interface UserGrants {
  /** unscoped role assignments (user + group roles) */
  global: string[];
  scoped: ScopedGrant[];
}

/**
 * Grants of a user: union of the user's own role assignments and those of all groups
 * the user belongs to. Assignments with a device-group scope are kept separately.
 */
export async function loadGrants(db: Db, userId: string): Promise<UserGrants> {
  const direct = await db
    .select({ permissions: roles.permissions, scope: userRoles.scopeDeviceGroupIds })
    .from(userRoles)
    .innerJoin(roles, eq(roles.id, userRoles.roleId))
    .where(eq(userRoles.userId, userId));
  const groupIds = (await db.select({ id: userGroups.groupId }).from(userGroups).where(eq(userGroups.userId, userId))).map((g) => g.id);
  const viaGroups = groupIds.length
    ? await db
        .select({ permissions: roles.permissions, scope: groupRoles.scopeDeviceGroupIds })
        .from(groupRoles)
        .innerJoin(roles, eq(roles.id, groupRoles.roleId))
        .where(inArray(groupRoles.groupId, groupIds))
    : [];

  const global = new Set<string>();
  const scoped: ScopedGrant[] = [];
  for (const r of [...direct, ...viaGroups]) {
    if (r.scope === null || r.scope === undefined) for (const p of r.permissions) global.add(p);
    else if (r.scope.length) scoped.push({ grants: [...r.permissions], deviceGroupIds: [...r.scope] });
  }
  return { global: [...global].sort(), scoped };
}

/** Backwards-compatible helper: global grants only. */
export async function loadEffectiveGrants(db: Db, userId: string): Promise<string[]> {
  return (await loadGrants(db, userId)).global;
}

/**
 * Intersection of two grant lists (API token restrictions). Empty `limit` means
 * "no restriction". Wildcards are expanded to concrete permissions.
 */
export function intersectGrants(owner: string[], limit: string[]): string[] {
  if (!limit.length) return owner;
  if (owner.includes('*') && limit.includes('*')) return ['*'];
  return ALL_PERMISSIONS.filter((p) => hasPermission(owner, p) && hasPermission(limit, p));
}
