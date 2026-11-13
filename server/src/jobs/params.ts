import { z } from 'zod';
import type { ScriptParameter } from '../db/schema.ts';

export const PARAM_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

export const ParameterDefSchema = z.object({
  name: z.string().regex(PARAM_NAME_RE, 'letters, digits, underscore; must not start with a digit'),
  label: z.string().max(200).optional(),
  type: z.enum(['string', 'number', 'boolean']),
  required: z.boolean().default(false),
  default: z.union([z.string().max(4000), z.number(), z.boolean()]).nullable().optional(),
});

export const ParameterDefsSchema = z
  .array(ParameterDefSchema)
  .max(50)
  .default([])
  .superRefine((defs, ctx) => {
    const seen = new Set<string>();
    defs.forEach((d, i) => {
      const key = d.name.toUpperCase();
      if (seen.has(key)) ctx.addIssue({ code: 'custom', path: [i, 'name'], message: `duplicate parameter ${d.name}` });
      seen.add(key);
      if (d.default !== undefined && d.default !== null && typeof d.default !== d.type) {
        ctx.addIssue({ code: 'custom', path: [i, 'default'], message: `default must be of type ${d.type}` });
      }
    });
  });

export type ParamValues = Record<string, string | number | boolean>;

/** Validates values against definitions and fills in defaults. Returns errors as strings. */
export function resolveParams(defs: ScriptParameter[], values: Record<string, unknown>): { values: ParamValues; errors: string[] } {
  const errors: string[] = [];
  const out: ParamValues = {};
  const byName = new Map(defs.map((d) => [d.name, d]));
  for (const k of Object.keys(values)) if (!byName.has(k)) errors.push(`unknown parameter "${k}"`);
  for (const d of defs) {
    const v = values[d.name];
    if (v === undefined || v === null || v === '') {
      if (d.default !== undefined && d.default !== null) out[d.name] = d.default;
      else if (d.required) errors.push(`parameter "${d.name}" is required`);
      continue;
    }
    if (typeof v !== d.type || (typeof v === 'number' && !Number.isFinite(v))) {
      errors.push(`parameter "${d.name}" must be of type ${d.type}`);
      continue;
    }
    if (typeof v === 'string' && v.length > 4000) {
      errors.push(`parameter "${d.name}" is too long`);
      continue;
    }
    out[d.name] = v as string | number | boolean;
  }
  return { values: out, errors };
}
