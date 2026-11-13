import type { Inventory } from './schema.ts';

export interface HistoryChange {
  category: string;
  change: 'added' | 'removed' | 'changed';
  itemKey: string;
  oldValue: unknown;
  newValue: unknown;
}

type Keyed = Map<string, unknown>;

/**
 * Projects an inventory onto the facts we track in the change history.
 * Volatile values (free disk space, service run state, IP addresses, logged-on
 * users) are deliberately excluded – they would flood the history.
 */
export function trackedFacts(inv: Inventory): Record<string, Keyed> {
  const m = <T>(items: T[], key: (t: T) => string, val: (t: T) => unknown): Keyed => {
    const map: Keyed = new Map();
    for (const i of items) map.set(key(i), val(i));
    return map;
  };
  const hw = inv.hardware;
  return {
    hardware: new Map<string, unknown>([
      ['manufacturer', hw.manufacturer],
      ['model', hw.model],
      ['serialNumber', hw.serialNumber],
      ['biosVersion', hw.biosVersion],
      ['cpu', hw.cpu.model],
      ['cpuCores', hw.cpu.cores],
      ['memoryBytes', hw.memoryBytes],
    ]),
    os: new Map<string, unknown>([
      ['name', inv.os.name],
      ['version', inv.os.version],
      ['build', inv.os.build],
      ['kernel', inv.os.kernel],
    ]),
    software: m(inv.software, (s) => `${s.name}${s.arch ? ` (${s.arch})` : ''}`, (s) => s.version),
    patch: m(inv.patches, (p) => p.id, () => true),
    service: m(inv.services, (s) => s.name, (s) => s.startMode),
    autostart: m(inv.autostart, (a) => `${a.location ?? ''}:${a.name}`, (a) => a.command),
    user: m(inv.localUsers, (u) => u.name, (u) => (u.disabled ? 'disabled' : 'enabled')),
    group: m(inv.localGroups, (g) => g.name, (g) => [...g.members].sort().join(', ')),
    disk: m(inv.disks, (d) => d.name, (d) => d.sizeBytes),
    security: securityFacts(inv),
  };
}

/** Security switches worth a history entry (no signature versions – they change daily). */
function securityFacts(inv: Inventory): Keyed {
  const out: Keyed = new Map();
  const s = inv.security;
  if (!s) return out;
  for (const v of s.encryption.volumes) out.set(`Verschlüsselung ${v.volume}`, v.encrypted === null ? null : v.encrypted ? (v.protection === false ? 'angehalten' : 'verschlüsselt') : 'unverschlüsselt');
  for (const a of s.antivirus) out.set(`Virenschutz ${a.name}`, a.enabled === false ? 'aus' : a.realtime === false ? 'Echtzeitschutz aus' : 'an');
  if (s.firewall.profiles.length) for (const p of s.firewall.profiles) out.set(`Firewall ${p.name}`, p.enabled === null ? null : p.enabled ? 'an' : 'aus');
  else if (s.firewall.enabled !== null) out.set('Firewall', s.firewall.enabled ? 'an' : 'aus');
  if (s.secureBoot !== null) out.set('Secure Boot', s.secureBoot ? 'an' : 'aus');
  return out;
}

const same = (a: unknown, b: unknown) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

export function diffInventories(prev: Inventory, next: Inventory): HistoryChange[] {
  const a = trackedFacts(prev);
  const b = trackedFacts(next);
  const out: HistoryChange[] = [];
  for (const category of Object.keys(b)) {
    const before = a[category] ?? new Map();
    const after = b[category]!;
    for (const [key, val] of after) {
      if (!before.has(key)) {
        // a scalar fact appearing for the first time (null → value) is a change, not an addition
        if (category === 'hardware' || category === 'os') {
          if (val !== null && val !== undefined) out.push({ category, change: 'changed', itemKey: key, oldValue: null, newValue: val });
        } else out.push({ category, change: 'added', itemKey: key, oldValue: null, newValue: val });
      } else if (!same(before.get(key), val)) {
        out.push({ category, change: 'changed', itemKey: key, oldValue: before.get(key) ?? null, newValue: val ?? null });
      }
    }
    for (const [key, val] of before) {
      if (!after.has(key)) out.push({ category, change: 'removed', itemKey: key, oldValue: val, newValue: null });
    }
  }
  return out;
}
