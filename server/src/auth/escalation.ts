import { inArray } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { groupRoles, roles } from '../db/schema.ts';
import { forbidden, HttpError } from '../http.ts';
import { loadGrants } from './rbac.ts';
import { grantMatches, MODULES, type Module, type Permission } from './permissions.ts';

/**
 * Privilege-escalation guard: an actor may only hand out (via role definitions or
 * role assignments) grants it holds itself.
 */
export function coversGrant(actorGrants: string[], grant: string): boolean {
  if (actorGrants.includes('*')) return true;
  if (grant === '*') return false;
  const [mod, action] = grant.split(':') as [string, string];
  if (action === '*') {
    if (actorGrants.includes(`${mod}:*`)) return true;
    // module wildcard is covered if the actor holds every concrete action of the module
    const actions = MODULES[mod as Module]?.actions ?? [];
    return actions.every((a) => actorGrants.some((g) => grantMatches(g, `${mod}:${a}` as Permission)));
  }
  return actorGrants.some((g) => grantMatches(g, grant as Permission));
}

export function assertCanGrant(actorGrants: string[], grants: string[]): void {
  const missing = grants.filter((g) => !coversGrant(actorGrants, g));
  if (missing.length) throw forbidden(`Cannot grant permissions you do not hold: ${missing.join(', ')}`);
}

/**
 * Taking control of an account (password, MFA reset, deactivation, deletion) is equivalent to
 * holding its rights: the actor must hold every grant of the target user, global or scoped.
 */
export async function assertCanManageUser(db: Db, actorGrants: string[], targetUserId: string): Promise<void> {
  const g = await loadGrants(db, targetUserId);
  const all = [...new Set([...g.global, ...g.scoped.flatMap((s) => s.grants)])];
  if (all.some((x) => !coversGrant(actorGrants, x))) throw forbidden('This user holds permissions you do not hold – you cannot change the password, MFA or status of this account');
}

/** Putting a user into a group hands out the group's roles → same check as a role assignment. */
export async function assertCanAssignGroups(db: Db, actorGrants: string[], groupIds: string[]): Promise<void> {
  if (!groupIds.length) return;
  const rows = await db.select({ roleId: groupRoles.roleId }).from(groupRoles).where(inArray(groupRoles.groupId, groupIds));
  await assertCanAssignRoles(db, actorGrants, [...new Set(rows.map((r) => r.roleId))]);
}

/** Loads the roles and asserts they exist and the actor may assign them. */
export async function assertCanAssignRoles(db: Db, actorGrants: string[], roleIds: string[]): Promise<void> {
  if (!roleIds.length) return;
  const found = await db.select({ id: roles.id, permissions: roles.permissions }).from(roles).where(inArray(roles.id, roleIds));
  if (found.length !== new Set(roleIds).size) throw new HttpError(400, 'invalid_reference', 'Unknown role id');
  assertCanGrant(actorGrants, found.flatMap((r) => r.permissions));
}
