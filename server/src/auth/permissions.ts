/**
 * Permission catalogue. A permission is "module:action".
 * Grants may additionally use wildcards: "module:*" or "*".
 */
export const ACTIONS = ['read', 'create', 'update', 'execute', 'approve', 'delete'] as const;
export type Action = (typeof ACTIONS)[number];

export const MODULES = {
  users: { label: 'Benutzer', actions: ['read', 'create', 'update', 'delete'] },
  groups: { label: 'Benutzergruppen', actions: ['read', 'create', 'update', 'delete'] },
  roles: { label: 'Rollen', actions: ['read', 'create', 'update', 'delete'] },
  audit: { label: 'Audit-Log', actions: ['read'] },
  devices: { label: 'Geräte', actions: ['read', 'create', 'update', 'delete'] },
  device_groups: { label: 'Gerätegruppen', actions: ['read', 'create', 'update', 'delete'] },
  inventory: { label: 'Inventar', actions: ['read', 'update'] },
  scripts: { label: 'Skripte', actions: ['read', 'create', 'update', 'execute', 'approve', 'delete'] },
  jobs: { label: 'Jobs', actions: ['read', 'create', 'update', 'execute', 'approve', 'delete'] },
  vulnerabilities: { label: 'Schwachstellen', actions: ['read', 'update'] },
  software: { label: 'Softwareverteilung', actions: ['read', 'create', 'update', 'execute', 'approve', 'delete'] },
  patches: { label: 'Patch-Management', actions: ['read', 'update', 'execute', 'approve'] },
  licenses: { label: 'Softwarelizenzen', actions: ['read', 'create', 'update', 'delete'] },
  reports: { label: 'Berichte', actions: ['read', 'create', 'update', 'delete'] },
  webhooks: { label: 'Webhooks', actions: ['read', 'create', 'update', 'delete'] },
  assets: { label: 'Assets (ohne Agent)', actions: ['read', 'create', 'update', 'delete'] },
  settings: { label: 'Einstellungen', actions: ['read', 'update'] },
} as const satisfies Record<string, { label: string; actions: readonly Action[] }>;

export type Module = keyof typeof MODULES;
export type Permission = {
  [M in Module]: `${M}:${(typeof MODULES)[M]['actions'][number]}`;
}[Module];

export const ALL_PERMISSIONS: Permission[] = (Object.keys(MODULES) as Module[]).flatMap((m) =>
  MODULES[m].actions.map((a) => `${m}:${a}` as Permission),
);

/** True if a grant string is syntactically valid (concrete permission or wildcard). */
export function isValidGrant(grant: string): boolean {
  if (grant === '*') return true;
  const [mod, action] = grant.split(':');
  if (!mod || !action || !(mod in MODULES)) return false;
  if (action === '*') return true;
  return (MODULES[mod as Module].actions as readonly string[]).includes(action);
}

export function grantMatches(grant: string, required: Permission): boolean {
  if (grant === '*' || grant === required) return true;
  const [mod, action] = grant.split(':');
  return action === '*' && required.startsWith(`${mod}:`);
}

export function hasPermission(grants: Iterable<string>, required: Permission): boolean {
  for (const g of grants) if (grantMatches(g, required)) return true;
  return false;
}

/** Built-in roles, created on first start. "Administrator" is immutable. */
export const SYSTEM_ROLES = [
  { name: 'Administrator', description: 'Vollzugriff auf alle Module', permissions: ['*'] },
  {
    name: 'Auditor',
    description: 'Lesezugriff auf alle Module inkl. Audit-Log',
    permissions: (Object.keys(MODULES) as Module[]).map((m) => `${m}:read`),
  },
  {
    name: 'Helpdesk',
    description: 'Geräte und Inventar ansehen, freigegebene Jobs ausführen',
    permissions: ['devices:read', 'device_groups:read', 'inventory:read', 'scripts:read', 'jobs:read', 'jobs:execute', 'assets:read'],
  },
] as const;
