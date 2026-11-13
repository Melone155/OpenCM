import { and, eq, inArray, isNotNull } from 'drizzle-orm';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import type { Directory, DirectoryUser } from '../auth/ldap.ts';
import { getDummyHash, verifyPassword } from '../auth/password.ts';
import { loadGrants } from '../auth/rbac.ts';
import type { SecretBox } from '../auth/secretbox.ts';
import { generateToken, hashToken } from '../auth/tokens.ts';
import { generateRecoveryCodes, generateTotpSecret, hashRecoveryCode, otpauthUri, verifyTotp } from '../auth/totp.ts';
import type { Config } from '../config.ts';
import type { Db } from '../db/client.ts';
import { groups, sessions, userGroups, users } from '../db/schema.ts';
import { conflict, HttpError, parse } from '../http.ts';
import { actorOf, principalOf, SESSION_COOKIE } from '../plugins/auth.ts';
import { getSecurity } from '../settings.ts';

const LoginBody = z.object({
  username: z.string().min(1).max(200),
  password: z.string().min(1).max(1000),
  otp: z.string().trim().max(64).optional(),
});
const Code = z.object({ code: z.string().trim().min(6).max(64) });

export interface AuthDeps {
  secretBox: SecretBox;
  directory: Directory | null;
}

export async function loadMe(app: FastifyInstance, req: FastifyRequest) {
  const p = principalOf(req);
  const [u] = await app.db
    .select({ id: users.id, username: users.username, displayName: users.displayName, email: users.email, authSource: users.authSource, mfaEnabled: users.mfaEnabled })
    .from(users)
    .where(eq(users.id, p.userId));
  if (!u) throw new HttpError(401, 'unauthorized', 'Authentication required');
  return {
    ...u,
    permissions: p.grants,
    scoped: p.scoped.map((s) => ({ permissions: s.grants, deviceGroupIds: s.deviceGroupIds })),
    mfaSetupRequired: p.mfaPending,
    via: p.via,
  };
}

type UserRow = typeof users.$inferSelect;

/** Creates/updates the local record of a directory user and syncs mapped group memberships. */
async function syncDirectoryUser(db: Db, d: DirectoryUser, requireGroup: boolean): Promise<UserRow | null> {
  const mapped = await db.select({ id: groups.id, ldapGroup: groups.ldapGroup }).from(groups).where(isNotNull(groups.ldapGroup));
  const memberDns = new Set(d.groups.map((g) => g.toLowerCase()));
  const target = mapped.filter((g) => memberDns.has(g.ldapGroup!.toLowerCase())).map((g) => g.id);
  if (requireGroup && !target.length) return null;

  return db.transaction(async (tx) => {
    const [existing] = await tx.select().from(users).where(eq(users.username, d.username));
    if (existing && existing.authSource !== 'ldap') return null; // never take over local accounts
    const values = { displayName: d.displayName, email: d.email, ldapDn: d.dn, updatedAt: new Date() };
    const [u] = existing
      ? await tx.update(users).set(values).where(eq(users.id, existing.id)).returning()
      : await tx.insert(users).values({ ...values, username: d.username, authSource: 'ldap', passwordHash: null }).returning();
    const mappedIds = mapped.map((g) => g.id);
    if (mappedIds.length) await tx.delete(userGroups).where(and(eq(userGroups.userId, u!.id), inArray(userGroups.groupId, mappedIds)));
    if (target.length) await tx.insert(userGroups).values(target.map((groupId) => ({ userId: u!.id, groupId }))).onConflictDoNothing();
    return u!;
  });
}

export function authRoutes(app: FastifyInstance, config: Config, deps: AuthDeps) {
  const { secretBox, directory } = deps;

  async function verifySecondFactor(u: UserRow, code: string): Promise<'totp' | 'recovery' | null> {
    if (/^\d{6}$/.test(code)) {
      if (!u.mfaSecretEnc) return null;
      const counter = verifyTotp(secretBox.open(u.mfaSecretEnc), code, new Date(), u.mfaLastCounter ?? null);
      if (counter === null) return null;
      // optimistic: only one login can consume this time step
      const [ok] = await app.db
        .update(users)
        .set({ mfaLastCounter: counter })
        .where(and(eq(users.id, u.id), u.mfaLastCounter === null ? undefined : eq(users.mfaLastCounter, u.mfaLastCounter)))
        .returning({ id: users.id });
      return ok ? 'totp' : null;
    }
    const h = hashRecoveryCode(code);
    if (!u.mfaRecoveryHashes.includes(h)) return null;
    await app.db
      .update(users)
      .set({ mfaRecoveryHashes: u.mfaRecoveryHashes.filter((x) => x !== h) })
      .where(eq(users.id, u.id));
    return 'recovery';
  }

  app.post(
    '/auth/login',
    { config: { rateLimit: { max: config.LOGIN_RATE_LIMIT_PER_MIN, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const body = parse(LoginBody, req.body);
      const fail = async (reason: string, code = 'invalid_credentials', message = 'Invalid username or password') => {
        await writeAudit(app.db, { type: 'system', id: null, name: body.username }, { action: 'auth.login_failed', details: { username: body.username, reason }, ip: req.ip });
        return new HttpError(401, code, message);
      };

      let [user] = await app.db.select().from(users).where(eq(users.username, body.username));
      let method: 'local' | 'ldap' = 'local';
      if (user?.authSource === 'local' || (!directory && (!user || user.authSource === 'local'))) {
        // Always run one Argon2 verification so response time does not reveal whether the user exists.
        const ok = await verifyPassword(user?.passwordHash ?? (await getDummyHash()), body.password);
        if (!user || !user.passwordHash || !ok) throw await fail('password');
      } else if (directory) {
        method = 'ldap';
        let d: DirectoryUser | null;
        try {
          d = await directory.authenticate(body.username, body.password);
        } catch (err) {
          req.log.error({ err }, 'LDAP authentication failed');
          throw new HttpError(503, 'directory_unavailable', 'Directory service is not reachable');
        }
        if (!d) throw await fail('ldap');
        const synced = await syncDirectoryUser(app.db, d, config.LDAP_REQUIRE_GROUP);
        if (!synced) throw await fail('ldap_no_mapped_group', 'not_authorized', 'Your directory account is not authorised for OpenCM');
        user = synced;
      } else {
        throw await fail('unknown_source');
      }
      if (!user.isActive) throw await fail('inactive');

      if (user.mfaEnabled) {
        if (!body.otp) {
          return reply.code(401).send({ error: { code: 'mfa_required', message: 'Enter the code from your authenticator app' } });
        }
        const factor = await verifySecondFactor(user, body.otp);
        if (!factor) throw await fail('otp', 'invalid_otp', 'Invalid or already used code');
        if (factor === 'recovery') {
          await writeAudit(app.db, { type: 'user', id: user.id, name: user.username }, { action: 'auth.mfa_recovery_code_used', ip: req.ip });
        }
      }

      const security = await getSecurity(app.db, config);
      const mfaPending = security.mfaRequired && !user.mfaEnabled;
      const token = generateToken('ocs');
      const expiresAt = new Date(Date.now() + config.SESSION_TTL_HOURS * 3600_000);
      await app.db.insert(sessions).values({
        userId: user.id,
        tokenHash: hashToken(token),
        expiresAt,
        mfaPending,
        ip: req.ip,
        userAgent: req.headers['user-agent']?.slice(0, 500) ?? null,
      });
      await app.db.update(users).set({ lastLoginAt: new Date() }).where(eq(users.id, user.id));
      await writeAudit(app.db, { type: 'user', id: user.id, name: user.username }, { action: 'auth.login', details: { method, mfa: user.mfaEnabled }, ip: req.ip });

      reply.setCookie(SESSION_COOKIE, token, { httpOnly: true, sameSite: 'strict', secure: config.COOKIE_SECURE, path: '/api', expires: expiresAt });
      const g = await loadGrants(app.db, user.id);
      return {
        token,
        expiresAt: expiresAt.toISOString(),
        mfaSetupRequired: mfaPending,
        user: {
          id: user.id,
          username: user.username,
          displayName: user.displayName,
          email: user.email,
          authSource: user.authSource,
          mfaEnabled: user.mfaEnabled,
          permissions: mfaPending ? [] : g.global,
          scoped: mfaPending ? [] : g.scoped.map((s) => ({ permissions: s.grants, deviceGroupIds: s.deviceGroupIds })),
          mfaSetupRequired: mfaPending,
          via: 'session' as const,
        },
      };
    },
  );

  app.post('/auth/logout', { preHandler: app.requireSession }, async (req, reply) => {
    const p = principalOf(req);
    if (p.sessionId) await app.db.delete(sessions).where(eq(sessions.id, p.sessionId));
    await writeAudit(app.db, actorOf(req), { action: 'auth.logout', ip: req.ip });
    reply.clearCookie(SESSION_COOKIE, { path: '/api' });
    return reply.code(204).send();
  });

  app.get('/auth/me', { preHandler: app.requireSession }, async (req) => loadMe(app, req));

  // ------------------------------------------------------------ MFA (own account, sessions only)

  const sessionUser = async (req: FastifyRequest) => {
    const p = principalOf(req);
    if (p.via !== 'session') throw new HttpError(403, 'session_required', 'MFA can only be managed with an interactive session');
    const [u] = await app.db.select().from(users).where(eq(users.id, p.userId));
    return { p, u: u! };
  };

  app.get('/auth/mfa', { preHandler: app.requireSession }, async (req) => {
    const { u } = await sessionUser(req);
    const s = await getSecurity(app.db, config);
    return { enabled: u.mfaEnabled, recoveryCodesLeft: u.mfaRecoveryHashes.length, required: s.mfaRequired };
  });

  app.post('/auth/mfa/setup', { preHandler: app.requireSession }, async (req) => {
    const { u } = await sessionUser(req);
    if (u.mfaEnabled) throw conflict('MFA is already enabled – disable it first to re-enrol');
    const secret = generateTotpSecret();
    await app.db.update(users).set({ mfaSecretEnc: secretBox.seal(secret), mfaLastCounter: null }).where(eq(users.id, u.id));
    return { secret, otpauthUri: otpauthUri(secret, u.username) };
  });

  app.post('/auth/mfa/enable', { preHandler: app.requireSession }, async (req) => {
    const { p, u } = await sessionUser(req);
    const { code } = parse(Code, req.body);
    if (u.mfaEnabled) throw conflict('MFA is already enabled');
    if (!u.mfaSecretEnc) throw conflict('Call /auth/mfa/setup first');
    const counter = verifyTotp(secretBox.open(u.mfaSecretEnc), code);
    if (counter === null) throw new HttpError(400, 'invalid_otp', 'Invalid code – check the time on your device');
    const codes = generateRecoveryCodes();
    await app.db.update(users).set({ mfaEnabled: true, mfaLastCounter: counter, mfaRecoveryHashes: codes.map(hashRecoveryCode) }).where(eq(users.id, u.id));
    if (p.sessionId) await app.db.update(sessions).set({ mfaPending: false }).where(eq(sessions.userId, u.id));
    await writeAudit(app.db, actorOf(req), { action: 'auth.mfa_enable', targetType: 'user', targetId: u.id, ip: req.ip });
    return { recoveryCodes: codes };
  });

  app.post('/auth/mfa/recovery-codes', { preHandler: app.requireAuth }, async (req) => {
    const { u } = await sessionUser(req);
    const { code } = parse(Code, req.body);
    if (!u.mfaEnabled || !(await verifySecondFactor(u, code))) throw new HttpError(400, 'invalid_otp', 'Invalid code');
    const codes = generateRecoveryCodes();
    await app.db.update(users).set({ mfaRecoveryHashes: codes.map(hashRecoveryCode) }).where(eq(users.id, u.id));
    await writeAudit(app.db, actorOf(req), { action: 'auth.mfa_recovery_codes', targetType: 'user', targetId: u.id, ip: req.ip });
    return { recoveryCodes: codes };
  });

  app.post('/auth/mfa/disable', { preHandler: app.requireAuth }, async (req, reply) => {
    const { u } = await sessionUser(req);
    const { code } = parse(Code, req.body);
    if ((await getSecurity(app.db, config)).mfaRequired) throw conflict('MFA is mandatory and cannot be disabled');
    if (!u.mfaEnabled || !(await verifySecondFactor(u, code))) throw new HttpError(400, 'invalid_otp', 'Invalid code');
    await app.db.update(users).set({ mfaEnabled: false, mfaSecretEnc: null, mfaRecoveryHashes: [], mfaLastCounter: null }).where(eq(users.id, u.id));
    await writeAudit(app.db, actorOf(req), { action: 'auth.mfa_disable', targetType: 'user', targetId: u.id, ip: req.ip });
    return reply.code(204).send();
  });
}
