import { z } from 'zod';

/**
 * Inventory payload sent by the agent (POST /agent/v1/inventory).
 * Lenient on optional fields (collectors differ per OS), strict on size.
 */
const str = (max = 500) => z.string().max(max);
const optStr = (max = 500) => z.string().max(max).nullish().transform((v) => v ?? null);
const optNum = z.number().finite().nonnegative().nullish().transform((v) => v ?? null);
const optBool = z.boolean().nullish().transform((v) => v ?? null);
const list = <T extends z.ZodType>(item: T, max: number) => z.array(item).max(max).default([]);

/** Security posture (M7). Absent for older agents. */
export const SecuritySchema = z.object({
  encryption: z
    .object({
      product: optStr(100), // BitLocker | FileVault | LUKS
      volumes: list(
        z.object({
          volume: str(200),
          system: optBool,
          encrypted: optBool,
          /** e.g. FullyEncrypted, EncryptionInProgress, FullyDecrypted */
          status: optStr(100),
          method: optStr(100),
          /** BitLocker protection on (false = suspended: key stored in clear) */
          protection: optBool,
        }),
        100,
      ),
    })
    .prefault({}),
  antivirus: list(
    z.object({
      name: str(200),
      enabled: optBool,
      realtime: optBool,
      upToDate: optBool,
      signatureVersion: optStr(100),
      signatureUpdatedAt: optStr(64),
      lastScanAt: optStr(64),
    }),
    20,
  ),
  firewall: z
    .object({
      product: optStr(100),
      enabled: optBool,
      profiles: list(z.object({ name: str(100), enabled: optBool }), 10),
    })
    .prefault({}),
  secureBoot: optBool,
  tpm: z.object({ present: optBool, ready: optBool, version: optStr(50) }).prefault({}),
});
export type Security = z.infer<typeof SecuritySchema>;

export const InventorySchema = z.object({
  collectedAt: z.coerce.date(),
  hardware: z
    .object({
      manufacturer: optStr(),
      model: optStr(),
      serialNumber: optStr(),
      chassis: optStr(),
      biosVendor: optStr(),
      biosVersion: optStr(),
      biosDate: optStr(),
      cpu: z
        .object({ model: optStr(), cores: optNum, logicalProcessors: optNum, mhz: optNum })
        .prefault({}),
      memoryBytes: optNum,
    })
    .prefault({}),
  os: z
    .object({
      name: optStr(),
      version: optStr(),
      build: optStr(),
      arch: optStr(),
      kernel: optStr(),
      installDate: optStr(),
      lastBoot: optStr(),
      /** Linux: ID from /etc/os-release (debian, ubuntu, rocky, almalinux, …) */
      distroId: optStr(50),
    })
    .prefault({}),
  disks: list(z.object({ name: str(), mount: optStr(), fsType: optStr(), sizeBytes: optNum, freeBytes: optNum }), 500),
  network: list(
    z.object({
      name: str(),
      mac: optStr(64),
      up: z.boolean().default(false),
      ipv4: list(str(64), 100),
      ipv6: list(str(64), 100),
    }),
    500,
  ),
  software: list(
    z.object({
      name: str(),
      version: str(200).default(''),
      publisher: str().default(''),
      installDate: optStr(64),
      source: str(50).default(''),
      arch: str(20).default(''),
      sourceName: optStr(200),
      sourceVersion: optStr(200),
    }),
    30_000,
  ),
  patches: list(z.object({ id: str(100), description: optStr(), installedOn: optStr(64) }), 10_000),
  services: list(
    z.object({ name: str(), displayName: optStr(), state: optStr(50), startMode: optStr(50) }),
    10_000,
  ),
  autostart: list(z.object({ name: str(), command: optStr(4000), location: optStr() }), 5_000),
  localUsers: list(
    z.object({ name: str(), fullName: optStr(), disabled: z.boolean().nullish().transform((v) => v ?? null), uid: optStr(100) }),
    10_000,
  ),
  localGroups: list(z.object({ name: str(), members: list(str(), 10_000) }), 5_000),
  loggedOnUsers: list(str(), 500),
  security: SecuritySchema.nullish().transform((v) => v ?? null),
});

export type Inventory = z.infer<typeof InventorySchema>;
