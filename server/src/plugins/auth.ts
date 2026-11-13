import { and, eq, gt, isNull, or } from 'drizzle-orm';
import type { FastifyInstance, FastifyReply, FastifyRequest, preHandlerAsyncHookHandler } from 'fastify';
import type { AuditActor } from '../audit.ts';
import { hasPermission, type Permission } from '../auth/permissions.ts';
import { intersectGrants, loadGrants, type ScopedGrant } from '../auth/rbac.ts';
import { hasAnyGrant, resolveDeviceScope, type DeviceScope } from '../auth/scope.ts';
import { hashToken } from '../auth/tokens.ts';
import { onlineThresholdSeconds, type Config } from '../config.ts';
import type { Db } from '../db/client.ts';
import { apiTokens, sessions, users } from '../db/schema.ts';
import { HttpError, forbidden } from '../http.ts';

export const SESSION_COOKIE = 'opencm_session';
const LAST_SEEN_UPDATE_MS = 5 * 60_000;

export interface Principal {
  userId: string;
  username: string;
  via: 'session' | 'token';
  sessionId: string | null;
  tokenId: string | null;
  tokenName: string | null;
  /** global grants (already intersected with API token restrictions) */
  grants: string[];
  /** grants restricted to device groups */
  scoped: ScopedGrant[];
  /** MFA is mandatory but not configured yet → only MFA setup is allowed */
  mfaPending: boolean;
  scopeCache: Map<string, DeviceScope>;
}

declare module 'fastify' {
  interface FastifyRequest {
    principal: Principal | null;
  }
  interface FastifyInstance {
    db: Db;
    /** authenticated (MFA setup completed if mandatory) */
    requireAuth: preHandlerAsyncHookHandler;
    /** authenticated, also during pending MFA setup (me, logout, MFA endpoints) */
    requireSession: preHandlerAsyncHookHandler;
    /** global permission (secure default: scoped role assignments do not count) */
    requirePermission: (p: Permission) => preHandlerAsyncHookHandler;
    /** permission globally or for some devices – the handler must filter by deviceScope() */
    requireScopedPermission: (p: Permission) => preHandlerAsyncHookHandler;
    deviceScope: (req: FastifyRequest, p: Permission) => Promise<DeviceScope>;
  }
}

export function extractToken(req: FastifyRequest): string | null {
  const h = req.headers.authorization;
  if (h?.startsWith('Bearer ')) return h.slice(7).trim() || null;
  return req.cookies?.[SESSION_COOKIE] ?? null;
}

export function actorOf(req: FastifyRequest): AuditActor {
  const p = req.principal;
  if (!p) return { type: 'system', id: null, name: 'anonymous' };
  return p.via === 'token' ? { type: 'api_token', id: p.userId, name: `${p.username} (Token „${p.tokenName}“)` } : { type: 'user', id: p.userId, name: p.username };
}

export function principalOf(req: FastifyRequest): Principal {
  if (!req.principal) throw new HttpError(401, 'unauthorized', 'Authentication required');
  return req.principal;
}

async function fromSession(db: Db, token: string, now: Date): Promise<Principal | null> {
  const [row] = await db
    .select({ sessionId: sessions.id, lastSeenAt: sessions.lastSeenAt, mfaPending: sessions.mfaPending, userId: users.id, username: users.username })
    .from(sessions)
    .innerJoin(users, eq(users.id, sessions.userId))
    .where(and(eq(sessions.tokenHash, hashToken(token)), gt(sessions.expiresAt, now), eq(users.isActive, true)));
  if (!row) return null;
  if (now.getTime() - row.lastSeenAt.getTime() > LAST_SEEN_UPDATE_MS) {
    await db.update(sessions).set({ lastSeenAt: now }).where(eq(sessions.id, row.sessionId));
  }
  const g = await loadGrants(db, row.userId);
  return {
    userId: row.userId,
    username: row.username,
    via: 'session',
    sessionId: row.sessionId,
    tokenId: null,
    tokenName: null,
    grants: g.global,
    scoped: g.scoped,
    mfaPending: row.mfaPending,
    scopeCache: new Map(),
  };
}

async function fromApiToken(db: Db, token: string, now: Date): Promise<Principal | null> {
  const [row] = await db
    .select({ id: apiTokens.id, name: apiTokens.name, permissions: apiTokens.permissions, lastUsedAt: apiTokens.lastUsedAt, userId: users.id, username: users.username })
    .from(apiTokens)
    .innerJoin(users, eq(users.id, apiTokens.userId))
    .where(
      and(
        eq(apiTokens.tokenHash, hashToken(token)),
        isNull(apiTokens.revokedAt),
        or(isNull(apiTokens.expiresAt), gt(apiTokens.expiresAt, now)),
        eq(users.isActive, true),
      ),
    );
  if (!row) return null;
  if (!row.lastUsedAt || now.getTime() - row.lastUsedAt.getTime() > LAST_SEEN_UPDATE_MS) {
    await db.update(apiTokens).set({ lastUsedAt: now }).where(eq(apiTokens.id, row.id));
  }
  const g = await loadGrants(db, row.userId);
  return {
    userId: row.userId,
    username: row.username,
    via: 'token',
    sessionId: null,
    tokenId: row.id,
    tokenName: row.name,
    grants: intersectGrants(g.global, row.permissions),
    scoped: g.scoped.map((s) => ({ ...s, grants: intersectGrants(s.grants, row.permissions) })).filter((s) => s.grants.length),
    mfaPending: false,
    scopeCache: new Map(),
  };
}

export function registerAuth(app: FastifyInstance, config: Config): void {
  app.decorateRequest('principal', null);
  const online = onlineThresholdSeconds(config);

  app.addHook('onRequest', async (req) => {
    const token = extractToken(req);
    if (!token) return;
    const now = new Date();
    req.principal = token.startsWith('oct_') ? await fromApiToken(app.db, token, now) : await fromSession(app.db, token, now);
  });

  const active = (req: FastifyRequest): Principal => {
    const p = principalOf(req);
    if (p.mfaPending) throw new HttpError(403, 'mfa_setup_required', 'Multi-factor authentication must be set up first');
    return p;
  };

  app.decorate('requireSession', async (req: FastifyRequest, _reply: FastifyReply) => {
    principalOf(req);
  });
  app.decorate('requireAuth', async (req: FastifyRequest, _reply: FastifyReply) => {
    active(req);
  });
  app.decorate('requirePermission', (perm: Permission) => async (req: FastifyRequest, _reply: FastifyReply) => {
    if (!hasPermission(active(req).grants, perm)) throw forbidden(`Missing permission ${perm}`);
  });
  app.decorate('requireScopedPermission', (perm: Permission) => async (req: FastifyRequest, _reply: FastifyReply) => {
    if (!hasAnyGrant(active(req), perm)) throw forbidden(`Missing permission ${perm}`);
  });
  app.decorate('deviceScope', (req: FastifyRequest, perm: Permission) => resolveDeviceScope(app.db, active(req), perm, online));
}
