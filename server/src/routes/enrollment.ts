import { and, desc, eq, gt, isNull, lt, or, sql } from 'drizzle-orm';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { writeAudit } from '../audit.ts';
import { generateToken, hashToken } from '../auth/tokens.ts';
import type { AgentBinaries } from '../agent/binaries.ts';
import { INSTALL_OS, installCommands, installScript, serverPin, sha256Hex, type InstallOs } from '../agent/install.ts';
import { agentPublicUrl, type Config } from '../config.ts';
import { deviceGroupMembers, deviceGroups, devices, enrollmentTokens } from '../db/schema.ts';
import { HttpError, IdParams, notFound, parse, Uuid } from '../http.ts';
import { CsrError, type Pki } from '../pki/ca.ts';
import type { Signer } from '../pki/signing.ts';
import { actorOf, principalOf } from '../plugins/auth.ts';
import { emitEvent } from '../webhooks/events.ts';

const CreateToken = z.object({
  name: z.string().trim().min(1).max(100),
  expiresInHours: z.number().int().min(1).max(24 * 365).default(24 * 7),
  maxUses: z.number().int().min(1).max(1_000_000).nullable().default(null),
  deviceGroupId: Uuid.nullable().default(null),
});

export const OS_VALUES = ['windows', 'linux', 'macos'] as const;
export const ARCH_VALUES = ['amd64', 'arm64'] as const;

const Enroll = z.object({
  token: z.string().min(10).max(200),
  csr: z.string().min(1).max(20_000),
  hostname: z.string().trim().min(1).max(255),
  os: z.enum(OS_VALUES),
  osVersion: z.string().max(200).default(''),
  arch: z.string().max(20).default(''),
  agentVersion: z.string().max(50).default(''),
  machineId: z.string().trim().min(8).max(200),
});

const tokenColumns = {
  id: enrollmentTokens.id,
  name: enrollmentTokens.name,
  createdBy: enrollmentTokens.createdBy,
  deviceGroupId: enrollmentTokens.deviceGroupId,
  maxUses: enrollmentTokens.maxUses,
  uses: enrollmentTokens.uses,
  expiresAt: enrollmentTokens.expiresAt,
  revokedAt: enrollmentTokens.revokedAt,
  createdAt: enrollmentTokens.createdAt,
};

export function enrollmentRoutes(app: FastifyInstance, config: Config, pki: Pki, signer: Signer, binaries: AgentBinaries) {
  const pin = serverPin(pki.caCertPem, signer.publicKey);
  const scriptFor = async (os: InstallOs) => installScript(os, config.PUBLIC_URL, pin, (await binaries.scan()).items);

  // Public – the generated install script contains no secret (the token is passed as argument).
  app.get('/agent-install/:os', async (req, reply) => {
    const { os } = parse(z.object({ os: z.enum(INSTALL_OS) }), req.params);
    return reply
      .header('content-type', os === 'windows' ? 'text/plain; charset=utf-8' : 'text/x-shellscript; charset=utf-8')
      .header('cache-control', 'no-store')
      .send(await scriptFor(os));
  });

  app.get('/enrollment-tokens', { preHandler: app.requirePermission('devices:create') }, async () => ({
    items: await app.db.select(tokenColumns).from(enrollmentTokens).orderBy(desc(enrollmentTokens.createdAt)),
  }));

  app.post('/enrollment-tokens', { preHandler: app.requirePermission('devices:create') }, async (req, reply) => {
    const body = parse(CreateToken, req.body);
    if (body.deviceGroupId) {
      const [g] = await app.db.select({ id: deviceGroups.id }).from(deviceGroups).where(eq(deviceGroups.id, body.deviceGroupId));
      if (!g) throw new HttpError(400, 'invalid_reference', 'Unknown device group id');
    }
    const token = generateToken('oce');
    const [row] = await app.db
      .insert(enrollmentTokens)
      .values({
        name: body.name,
        tokenHash: hashToken(token),
        createdBy: principalOf(req).userId,
        deviceGroupId: body.deviceGroupId,
        maxUses: body.maxUses,
        expiresAt: new Date(Date.now() + body.expiresInHours * 3600_000),
      })
      .returning(tokenColumns);
    await writeAudit(app.db, actorOf(req), {
      action: 'enrollment_token.create',
      targetType: 'enrollment_token',
      targetId: row!.id,
      details: { name: body.name, maxUses: body.maxUses, expiresAt: row!.expiresAt },
      ip: req.ip,
    });
    const sha = {} as Record<InstallOs, string>;
    for (const os of INSTALL_OS) sha[os] = sha256Hex(await scriptFor(os));
    return reply.code(201).send({ ...row, token, installCommands: installCommands(config.PUBLIC_URL, token, sha) });
  });

  app.delete('/enrollment-tokens/:id', { preHandler: app.requirePermission('devices:create') }, async (req, reply) => {
    const { id } = parse(IdParams, req.params);
    const [row] = await app.db
      .update(enrollmentTokens)
      .set({ revokedAt: new Date() })
      .where(and(eq(enrollmentTokens.id, id), isNull(enrollmentTokens.revokedAt)))
      .returning({ id: enrollmentTokens.id, name: enrollmentTokens.name });
    if (!row) {
      const [exists] = await app.db.select({ id: enrollmentTokens.id }).from(enrollmentTokens).where(eq(enrollmentTokens.id, id));
      if (!exists) throw notFound('Enrollment token');
    } else {
      await writeAudit(app.db, actorOf(req), { action: 'enrollment_token.revoke', targetType: 'enrollment_token', targetId: id, details: { name: row.name }, ip: req.ip });
    }
    return reply.code(204).send();
  });

  // Public: the enrollment token is the credential.
  app.post(
    '/agent/enroll',
    { config: { rateLimit: { max: config.ENROLL_RATE_LIMIT_PER_MIN, timeWindow: '1 minute' } } },
    async (req) => {
      const body = parse(Enroll, req.body);
      const now = new Date();

      // Every machineId exists once (REV-004/005): an enrollment token never takes over or
      // reactivates a registered device. Checked again inside the transaction (unique index).
      const reject = async (existing: { id: string; status: string }) => {
        await writeAudit(app.db, { type: 'agent', id: null, name: body.hostname }, {
          action: 'device.enroll_rejected',
          targetType: 'device',
          targetId: existing.id,
          details: { reason: 'machine_id_already_registered', deviceStatus: existing.status, hostname: body.hostname },
          ip: req.ip,
        });
        return new HttpError(409, 'device_already_enrolled', 'A device with this machine id is already registered. An administrator must delete it in OpenCM before this machine can enroll again.');
      };
      const [known] = await app.db.select({ id: devices.id, status: devices.status }).from(devices).where(eq(devices.machineId, body.machineId));
      if (known) throw await reject(known);

      const result = await app.db.transaction(async (tx) => {
        // Atomically consume one use of a valid token.
        const [tok] = await tx
          .update(enrollmentTokens)
          .set({ uses: sql`${enrollmentTokens.uses} + 1` })
          .where(
            and(
              eq(enrollmentTokens.tokenHash, hashToken(body.token)),
              isNull(enrollmentTokens.revokedAt),
              gt(enrollmentTokens.expiresAt, now),
              or(isNull(enrollmentTokens.maxUses), lt(enrollmentTokens.uses, enrollmentTokens.maxUses)),
            ),
          )
          .returning({ id: enrollmentTokens.id, name: enrollmentTokens.name, deviceGroupId: enrollmentTokens.deviceGroupId });
        if (!tok) throw new HttpError(401, 'invalid_enrollment_token', 'Enrollment token is invalid, expired, revoked or used up');

        const values = {
          hostname: body.hostname,
          os: body.os,
          osVersion: body.osVersion,
          arch: body.arch,
          agentVersion: body.agentVersion || null,
          status: 'active',
          inventoryRequested: true,
          lastIp: req.ip,
          updatedAt: now,
        };
        // onConflictDoNothing: a concurrent enrollment of the same machineId loses instead of taking over
        const [d] = await tx.insert(devices).values({ ...values, machineId: body.machineId }).onConflictDoNothing({ target: devices.machineId }).returning({ id: devices.id });
        if (!d) throw new HttpError(409, 'device_already_enrolled', 'A device with this machine id is already registered.');
        const deviceId = d.id;

        let issued;
        try {
          issued = await pki.signClientCsr(body.csr, deviceId, config.AGENT_CERT_DAYS);
        } catch (err) {
          if (err instanceof CsrError) throw new HttpError(400, 'invalid_csr', err.message);
          throw err;
        }
        await tx
          .update(devices)
          .set({ certFingerprint: issued.fingerprint, certSerial: issued.serial, certExpiresAt: issued.notAfter })
          .where(eq(devices.id, deviceId));
        if (tok.deviceGroupId) {
          await tx.insert(deviceGroupMembers).values({ deviceGroupId: tok.deviceGroupId, deviceId }).onConflictDoNothing();
        }
        return { deviceId, issued, tok };
      });

      await writeAudit(app.db, { type: 'agent', id: result.deviceId, name: body.hostname }, {
        action: 'device.enroll',
        targetType: 'device',
        targetId: result.deviceId,
        details: { tokenId: result.tok.id, tokenName: result.tok.name, os: body.os, serial: result.issued.serial },
        ip: req.ip,
      });
      await emitEvent(app.db, 'device.enrolled', { deviceId: result.deviceId, hostname: body.hostname, os: body.os, reenrolled: false, token: result.tok.name });

      return {
        deviceId: result.deviceId,
        certificate: result.issued.pem,
        caCertificate: pki.caCertPem,
        certificateExpiresAt: result.issued.notAfter.toISOString(),
        agentUrl: agentPublicUrl(config),
        heartbeatSeconds: config.AGENT_HEARTBEAT_SECONDS,
        signingPublicKey: signer.publicKey,
      };
    },
  );
}
