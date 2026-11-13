import { and, desc, eq } from 'drizzle-orm';
import type { Db } from '../db/client.ts';
import { customFields, scripts, scriptVersions } from '../db/schema.ts';
import { HttpError } from '../http.ts';
import { resolveParams } from './params.ts';

export interface StepInput {
  scriptId: string;
  version?: number;
  params: Record<string, unknown>;
  continueOnError: boolean;
  customFieldId: string | null;
}

export interface ResolvedStep {
  scriptVersionId: string;
  params: Record<string, string | number | boolean>;
  continueOnError: boolean;
  customFieldId: string | null;
}

/** Validates job steps: approved versions only, parameters checked, custom fields exist. */
export async function resolveJobSteps(db: Db, steps: StepInput[]): Promise<ResolvedStep[]> {
  const out: ResolvedStep[] = [];
  for (const [i, s] of steps.entries()) {
    const [script] = await db.select().from(scripts).where(eq(scripts.id, s.scriptId));
    if (!script) throw new HttpError(400, 'invalid_reference', `Step ${i + 1}: unknown script`);
    const versionWhere = s.version
      ? and(eq(scriptVersions.scriptId, s.scriptId), eq(scriptVersions.version, s.version))
      : and(eq(scriptVersions.scriptId, s.scriptId), eq(scriptVersions.status, 'approved'));
    const [v] = await db.select().from(scriptVersions).where(versionWhere).orderBy(desc(scriptVersions.version)).limit(1);
    if (!v) throw new HttpError(400, 'script_not_approved', `Step ${i + 1}: "${script.name}" has no ${s.version ? `version ${s.version}` : 'approved version'}`);
    if (v.status !== 'approved') throw new HttpError(400, 'script_not_approved', `Step ${i + 1}: "${script.name}" v${v.version} is ${v.status} – only approved versions can be used in jobs`);
    const { values, errors } = resolveParams(v.parameters, s.params);
    if (errors.length) throw new HttpError(400, 'invalid_parameters', `Step ${i + 1} (${script.name}): ${errors.join('; ')}`);
    if (s.customFieldId) {
      const [f] = await db.select({ id: customFields.id }).from(customFields).where(eq(customFields.id, s.customFieldId));
      if (!f) throw new HttpError(400, 'invalid_reference', `Step ${i + 1}: unknown custom field`);
    }
    out.push({ scriptVersionId: v.id, params: values, continueOnError: s.continueOnError, customFieldId: s.customFieldId });
  }
  return out;
}
