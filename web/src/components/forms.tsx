import { useState } from 'react';
import { api, unwrap, type Schemas } from '../api/client';
import { OS_LABEL } from '../format';
import { useLoad } from '../hooks';

type Param = Schemas['ScriptParameter'];
export type ParamValues = Record<string, string | number | boolean>;

/** Input form for script parameter values. */
export function ParamsForm({ defs, values, onChange }: { defs: Param[]; values: ParamValues; onChange: (v: ParamValues) => void }) {
  if (!defs.length) return <p className="muted">Dieses Skript hat keine Parameter.</p>;
  const set = (name: string, v: string | number | boolean | undefined) => {
    const next = { ...values };
    if (v === undefined || v === '') delete next[name];
    else next[name] = v;
    onChange(next);
  };
  return (
    <div className="form-grid">
      {defs.map((d) => (
        <label key={d.name} className={d.type === 'boolean' ? 'check' : undefined}>
          {d.type === 'boolean' ? (
            <>
              <input type="checkbox" checked={Boolean(values[d.name] ?? d.default ?? false)} onChange={(e) => set(d.name, e.target.checked)} />
              {d.label || d.name}
            </>
          ) : (
            <>
              {d.label || d.name}
              {d.required && ' *'}
              <input
                type={d.type === 'number' ? 'number' : 'text'}
                value={values[d.name] === undefined ? '' : String(values[d.name])}
                placeholder={d.default !== undefined && d.default !== null ? `Standard: ${String(d.default)}` : ''}
                onChange={(e) => set(d.name, d.type === 'number' ? (e.target.value === '' ? undefined : Number(e.target.value)) : e.target.value)}
              />
              <small className="muted">$env:OPENCM_PARAM_{d.name.toUpperCase()}</small>
            </>
          )}
        </label>
      ))}
    </div>
  );
}

/** Editor for parameter definitions of a script version. */
export function ParamsEditor({ defs, onChange }: { defs: Param[]; onChange: (d: Param[]) => void }) {
  const update = (i: number, patch: Partial<Param>) => onChange(defs.map((d, j) => (i === j ? { ...d, ...patch } : d)));
  return (
    <div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Bezeichnung</th>
              <th>Typ</th>
              <th>Pflicht</th>
              <th>Standard</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {defs.map((d, i) => (
              <tr key={i}>
                <td>
                  <input value={d.name} onChange={(e) => update(i, { name: e.target.value })} placeholder="Name" />
                </td>
                <td>
                  <input value={d.label ?? ''} onChange={(e) => update(i, { label: e.target.value })} />
                </td>
                <td>
                  <select value={d.type} onChange={(e) => update(i, { type: e.target.value as Param['type'], default: null })}>
                    <option value="string">Text</option>
                    <option value="number">Zahl</option>
                    <option value="boolean">Ja/Nein</option>
                  </select>
                </td>
                <td>
                  <input type="checkbox" checked={!!d.required} onChange={(e) => update(i, { required: e.target.checked })} />
                </td>
                <td>
                  {d.type === 'boolean' ? (
                    <input type="checkbox" checked={d.default === true} onChange={(e) => update(i, { default: e.target.checked })} />
                  ) : (
                    <input
                      type={d.type === 'number' ? 'number' : 'text'}
                      value={d.default === null || d.default === undefined ? '' : String(d.default)}
                      onChange={(e) => update(i, { default: e.target.value === '' ? null : d.type === 'number' ? Number(e.target.value) : e.target.value })}
                    />
                  )}
                </td>
                <td>
                  <button type="button" className="link danger" onClick={() => onChange(defs.filter((_, j) => j !== i))}>
                    Entfernen
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button type="button" className="link" onClick={() => onChange([...defs, { name: '', type: 'string', required: false }])}>
        + Parameter
      </button>
    </div>
  );
}

/** Multi-select of devices with search. */
export function DevicePicker({ selected, onChange, os }: { selected: string[]; onChange: (ids: string[]) => void; os?: string[] }) {
  const [search, setSearch] = useState('');
  const devices = useLoad(() => unwrap(api.GET('/devices', { params: { query: { search: search || undefined, status: 'active', limit: 200 } } })), [search]);
  const items = (devices.data?.items ?? []).filter((d) => !os || os.includes(d.os));
  const toggle = (id: string) => onChange(selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id]);
  return (
    <div className="picker">
      <input placeholder="Geräte suchen …" value={search} onChange={(e) => setSearch(e.target.value)} />
      <div className="picker-list">
        {items.map((d) => (
          <label key={d.id} className="check">
            <input type="checkbox" checked={selected.includes(d.id)} onChange={() => toggle(d.id)} />
            {d.hostname} <span className="muted">{OS_LABEL[d.os]}</span>
            {d.online ? <span className="badge ok">online</span> : null}
          </label>
        ))}
        {items.length === 0 && <span className="muted">Keine Geräte</span>}
      </div>
      <div className="muted">{selected.length} ausgewählt</div>
    </div>
  );
}

type Filter = Schemas['GroupFilter'];
type Rule = Filter['rules'][number];

const FIELDS: { value: string; label: string; ops: string[] }[] = [
  { value: 'hostname', label: 'Hostname', ops: ['eq', 'ne', 'contains', 'startsWith', 'exists', 'notExists'] },
  { value: 'os', label: 'Betriebssystem', ops: ['eq', 'ne', 'in'] },
  { value: 'osVersion', label: 'OS-Version', ops: ['eq', 'ne', 'contains', 'startsWith'] },
  { value: 'manufacturer', label: 'Hersteller', ops: ['eq', 'ne', 'contains', 'exists', 'notExists'] },
  { value: 'model', label: 'Modell', ops: ['eq', 'ne', 'contains', 'exists', 'notExists'] },
  { value: 'arch', label: 'Architektur', ops: ['eq', 'ne'] },
  { value: 'agentVersion', label: 'Agent-Version', ops: ['eq', 'ne', 'startsWith'] },
  { value: 'loggedOnUser', label: 'Angemeldeter Benutzer', ops: ['eq', 'contains', 'exists', 'notExists'] },
  { value: 'online', label: 'Online', ops: ['eq'] },
  { value: 'software', label: 'Software', ops: ['installed', 'notInstalled'] },
  { value: 'encryption', label: 'Verschlüsselung', ops: ['eq', 'ne'] },
  { value: 'antivirus', label: 'Virenschutz', ops: ['eq', 'ne'] },
  { value: 'firewall', label: 'Firewall', ops: ['eq', 'ne'] },
  { value: 'securityCompliant', label: 'Sicherheitsstatus konform', ops: ['eq'] },
];

/** Fixed value lists (select instead of free text). */
const FIELD_VALUES: Record<string, { value: string; label: string }[]> = {
  os: [
    { value: 'windows', label: 'Windows' },
    { value: 'linux', label: 'Linux' },
    { value: 'macos', label: 'macOS' },
  ],
  encryption: [
    { value: 'encrypted', label: 'verschlüsselt' },
    { value: 'partial', label: 'teilweise' },
    { value: 'unencrypted', label: 'unverschlüsselt' },
    { value: 'unknown', label: 'unbekannt' },
  ],
  antivirus: [
    { value: 'ok', label: 'aktiv & aktuell' },
    { value: 'outdated', label: 'veraltet' },
    { value: 'disabled', label: 'deaktiviert' },
    { value: 'missing', label: 'fehlt' },
    { value: 'unknown', label: 'unbekannt' },
  ],
  firewall: [
    { value: 'on', label: 'an' },
    { value: 'partial', label: 'teilweise' },
    { value: 'off', label: 'aus' },
    { value: 'unknown', label: 'unbekannt' },
  ],
};
const BOOL_FIELDS = ['online', 'securityCompliant'];
const OP_LABEL: Record<string, string> = {
  eq: 'ist',
  ne: 'ist nicht',
  contains: 'enthält',
  startsWith: 'beginnt mit',
  in: 'ist eines von',
  exists: 'ist gesetzt',
  notExists: 'ist leer',
  gt: 'größer als',
  lt: 'kleiner als',
  installed: 'installiert',
  notInstalled: 'nicht installiert',
};
const CUSTOM_OPS = ['eq', 'ne', 'contains', 'gt', 'lt', 'exists', 'notExists'];

/** Builder for dynamic group filters. */
export function FilterBuilder({ filter, onChange, customFields }: { filter: Filter; onChange: (f: Filter) => void; customFields: Schemas['CustomField'][] }) {
  const fields = [...FIELDS, ...customFields.map((c) => ({ value: `custom:${c.name}`, label: `Feld: ${c.label}`, ops: CUSTOM_OPS }))];
  const update = (i: number, patch: Partial<Rule>) => onChange({ ...filter, rules: filter.rules.map((r, j) => (i === j ? { ...r, ...patch } : r)) });
  return (
    <div className="filter-builder">
      <label className="inline">
        Geräte, die
        <select value={filter.match ?? 'all'} onChange={(e) => onChange({ ...filter, match: e.target.value as 'all' | 'any' })}>
          <option value="all">alle</option>
          <option value="any">mindestens eine</option>
        </select>
        Bedingungen erfüllen:
      </label>
      {filter.rules.map((r, i) => {
        const def = fields.find((f) => f.value === r.field) ?? FIELDS[0]!;
        const noValue = ['exists', 'notExists'].includes(r.op);
        return (
          <div key={i} className="form-inline rule">
            <select value={r.field} onChange={(e) => update(i, { field: e.target.value, op: (fields.find((f) => f.value === e.target.value) ?? FIELDS[0]!).ops[0]!, value: undefined })}>
              {fields.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>
            <select value={r.op} onChange={(e) => update(i, { op: e.target.value })}>
              {def.ops.map((o) => (
                <option key={o} value={o}>
                  {OP_LABEL[o]}
                </option>
              ))}
            </select>
            {BOOL_FIELDS.includes(r.field) ? (
              <select value={String(r.value ?? true)} onChange={(e) => update(i, { value: e.target.value === 'true' })}>
                <option value="true">ja</option>
                <option value="false">nein</option>
              </select>
            ) : FIELD_VALUES[r.field] && r.op !== 'in' ? (
              <select value={String(r.value ?? '')} onChange={(e) => update(i, { value: e.target.value })}>
                <option value="">–</option>
                {FIELD_VALUES[r.field]!.map((v) => (
                  <option key={v.value} value={v.value}>
                    {v.label}
                  </option>
                ))}
              </select>
            ) : noValue ? null : (
              <input
                value={Array.isArray(r.value) ? r.value.join(', ') : r.value === undefined ? '' : String(r.value)}
                placeholder={r.op === 'in' ? 'a, b, c' : 'Wert'}
                type={['gt', 'lt'].includes(r.op) ? 'number' : 'text'}
                onChange={(e) =>
                  update(i, {
                    value:
                      r.op === 'in'
                        ? e.target.value.split(',').map((s) => s.trim()).filter(Boolean)
                        : ['gt', 'lt'].includes(r.op)
                          ? Number(e.target.value)
                          : e.target.value,
                  })
                }
              />
            )}
            <button type="button" className="link danger" disabled={filter.rules.length === 1} onClick={() => onChange({ ...filter, rules: filter.rules.filter((_, j) => j !== i) })}>
              Entfernen
            </button>
          </div>
        );
      })}
      <button type="button" className="link" onClick={() => onChange({ ...filter, rules: [...filter.rules, { field: 'hostname', op: 'contains', value: '' }] })}>
        + Bedingung
      </button>
    </div>
  );
}
