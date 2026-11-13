import type { DetectionRule } from '../db/schema.ts';
import { compareVersions } from '../vuln/version.ts';
import { globToRegex } from './generate.ts';

export interface InstalledSoftware {
  name: string;
  version: string;
}

/**
 * Server-side evaluation of the inventory-based rules ("software"). Other rule types
 * (file, registry, command) can only be checked on the device.
 *  - true / false: all software rules evaluated
 *  - null: the package has no software rule → unknown from inventory alone
 */
export function detectFromInventory(rules: DetectionRule[], software: InstalledSoftware[]): boolean | null {
  const sw = rules.filter((r): r is Extract<DetectionRule, { type: 'software' }> => r.type === 'software');
  if (!sw.length) return null;
  return sw.every((r) => {
    const re = new RegExp(globToRegex(r.name), 'i');
    return software.some((s) => {
      if (!re.test(s.name)) return false;
      if (!r.version) return true;
      const c = compareVersions(s.version, r.version);
      return r.operator === 'eq' ? c === 0 : r.operator === 'lt' ? c < 0 : c >= 0;
    });
  });
}
