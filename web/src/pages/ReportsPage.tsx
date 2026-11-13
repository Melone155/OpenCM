import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, unwrap, type Schemas } from '../api/client';
import { useAuth } from '../auth';
import { fmtDate, useLoad } from '../hooks';
import { DeleteButton } from './UsersPage';

type Source = Schemas['ReportSource'];
type Filter = Schemas['ReportFilter'];
type Result = Schemas['ReportResult'];
type Op = Filter['op'];

const OPS: Record<string, { op: Op; label: string }[]> = {
  string: [
    { op: 'contains', label: 'enthält' },
    { op: 'eq', label: 'ist' },
    { op: 'ne', label: 'ist nicht' },
    { op: 'starts', label: 'beginnt mit' },
    { op: 'in', label: 'ist eines von (Komma)' },
    { op: 'empty', label: 'ist leer' },
    { op: 'notempty', label: 'ist nicht leer' },
  ],
  number: [
    { op: 'eq', label: '=' },
    { op: 'ne', label: '≠' },
    { op: 'gt', label: '>' },
    { op: 'gte', label: '≥' },
    { op: 'lt', label: '<' },
    { op: 'lte', label: '≤' },
    { op: 'empty', label: 'ist leer' },
    { op: 'notempty', label: 'ist nicht leer' },
  ],
  date: [
    { op: 'gte', label: 'ab' },
    { op: 'lt', label: 'vor' },
    { op: 'empty', label: 'ist leer' },
    { op: 'notempty', label: 'ist nicht leer' },
  ],
  boolean: [{ op: 'eq', label: 'ist' }],
};

export function ReportsPage() {
  const list = useLoad(() => unwrap(api.GET('/reports')));
  const { can } = useAuth();
  return (
    <>
      <div className="toolbar">
        <h1>Berichte</h1>
        {can('reports:create') && (
          <Link className="button" to="/reports/new">
            Neuer Bericht
          </Link>
        )}
      </div>
      {list.error && <div className="error">{list.error}</div>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Bericht</th>
              <th>Quelle</th>
              <th>Sichtbarkeit</th>
              <th>Geändert</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((r) => (
              <tr key={r.id}>
                <td>
                  <Link to={`/reports/${r.id}`}>{r.name}</Link>
                  {r.description && <div className="muted small">{r.description}</div>}
                </td>
                <td>{r.sourceLabel}</td>
                <td>{r.shared ? `geteilt${r.mine ? '' : ` von ${r.ownerName ?? '–'}`}` : 'privat'}</td>
                <td>{fmtDate(r.updatedAt)}</td>
                <td className="actions">
                  <a className="link" href={`/api/v1/reports/${r.id}/run?format=csv`}>
                    CSV
                  </a>
                </td>
              </tr>
            ))}
            {list.data?.items.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  Noch keine Berichte. Mit „Neuer Bericht“ Quelle, Spalten und Filter wählen.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

type Def = { source: string; columns: string[]; filters: Filter[]; sort: { field: string; dir: 'asc' | 'desc' } | null };

export function ReportEditor() {
  const { id } = useParams();
  const isNew = !id || id === 'new';
  const navigate = useNavigate();
  const { me } = useAuth();
  const sources = useLoad(() => unwrap(api.GET('/report-sources')));
  const saved = useLoad(() => (isNew ? Promise.resolve(null) : unwrap(api.GET('/reports/{id}', { params: { path: { id: id! } } }))), [id]);
  const [def, setDef] = useState<Def | null>(null);
  const [meta, setMeta] = useState({ name: '', description: '', shared: false });
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    if (def) return;
    if (!isNew && saved.data) {
      setDef({ source: saved.data.source, columns: saved.data.columns, filters: saved.data.filters, sort: saved.data.sort ?? null });
      setMeta({ name: saved.data.name, description: saved.data.description, shared: saved.data.shared });
    } else if (isNew && sources.data?.items[0]) {
      const s = sources.data.items[0];
      setDef({ source: s.key, columns: s.defaultColumns, filters: [], sort: null });
    }
  }, [isNew, saved.data, sources.data, def]);

  const source: Source | undefined = sources.data?.items.find((s) => s.key === def?.source);
  const colType = (k: string) => source?.columns.find((c) => c.key === k)?.type ?? 'string';
  const editable = isNew || (saved.data && (saved.data.createdBy === me?.id || saved.data.mine));

  async function preview() {
    if (!def) return;
    setError(null);
    try {
      setResult(await unwrap(api.POST('/reports/preview', { body: { ...def, limit: 200 } })));
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    if (def) void preview();
  }, [def?.source]); // eslint-disable-line react-hooks/exhaustive-deps

  async function save() {
    if (!def) return;
    setError(null);
    try {
      if (isNew) {
        const r = await unwrap(api.POST('/reports', { body: { ...def, ...meta } }));
        navigate(`/reports/${r.id}`);
      } else {
        await unwrap(api.PATCH('/reports/{id}', { params: { path: { id: id! } }, body: { ...def, ...meta } }));
        setMsg('Gespeichert.');
      }
    } catch (e) {
      setError((e as Error).message);
    }
  }

  if (!def || !sources.data) return <div className="muted">{sources.error ?? saved.error ?? 'Lade …'}</div>;
  const setFilter = (i: number, f: Filter) => setDef({ ...def, filters: def.filters.map((x, j) => (i === j ? f : x)) });

  return (
    <>
      <div className="toolbar">
        <h1>
          <Link to="/reports" className="muted">
            Berichte
          </Link>{' '}
          / {isNew ? 'Neu' : meta.name}
        </h1>
        {!isNew && (
          <a className="button link" href={`/api/v1/reports/${id}/run?format=csv`}>
            Export CSV
          </a>
        )}
        {!isNew && editable && <DeleteButton onConfirm={() => unwrap(api.DELETE('/reports/{id}', { params: { path: { id: id! } } })).then(() => navigate('/reports'))} />}
      </div>
      {msg && <div className="card">{msg}</div>}
      {error && <div className="error">{error}</div>}

      <div className="card">
        <div className="form-inline">
          <label className="inline">
            Quelle
            <select
              value={def.source}
              onChange={(e) => {
                const s = sources.data!.items.find((x) => x.key === e.target.value)!;
                setResult(null);
                setDef({ source: s.key, columns: s.defaultColumns, filters: [], sort: null });
              }}
            >
              {sources.data.items.map((s) => (
                <option key={s.key} value={s.key}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
          <label className="inline">
            Sortierung
            <select value={def.sort?.field ?? ''} onChange={(e) => setDef({ ...def, sort: e.target.value ? { field: e.target.value, dir: def.sort?.dir ?? 'asc' } : null })}>
              <option value="">– erste Spalte –</option>
              {source?.columns.map((c) => (
                <option key={c.key} value={c.key}>
                  {c.label}
                </option>
              ))}
            </select>
            {def.sort && (
              <select value={def.sort.dir} onChange={(e) => setDef({ ...def, sort: { ...def.sort!, dir: e.target.value as 'asc' } })}>
                <option value="asc">aufsteigend</option>
                <option value="desc">absteigend</option>
              </select>
            )}
          </label>
        </div>
        <h3>Spalten</h3>
        <div className="check-grid">
          {source?.columns.map((c) => (
            <label key={c.key} className="check">
              <input
                type="checkbox"
                checked={def.columns.includes(c.key)}
                onChange={(e) => setDef({ ...def, columns: e.target.checked ? [...def.columns, c.key] : def.columns.filter((x) => x !== c.key) })}
              />
              {c.label}
            </label>
          ))}
        </div>
        <h3>Filter (alle müssen zutreffen)</h3>
        {def.filters.map((f, i) => {
          const type = colType(f.field);
          const needsValue = !['empty', 'notempty'].includes(f.op);
          return (
            <div key={i} className="form-inline rule">
              <select value={f.field} onChange={(e) => setFilter(i, { field: e.target.value, op: OPS[colType(e.target.value)]![0]!.op, value: colType(e.target.value) === 'boolean' ? true : '' })}>
                {source?.columns.map((c) => (
                  <option key={c.key} value={c.key}>
                    {c.label}
                  </option>
                ))}
              </select>
              <select value={f.op} onChange={(e) => setFilter(i, { ...f, op: e.target.value as Op })}>
                {OPS[type]!.map((o) => (
                  <option key={o.op} value={o.op}>
                    {o.label}
                  </option>
                ))}
              </select>
              {needsValue && type === 'boolean' && (
                <select value={String(f.value)} onChange={(e) => setFilter(i, { ...f, value: e.target.value === 'true' })}>
                  <option value="true">ja</option>
                  <option value="false">nein</option>
                </select>
              )}
              {needsValue && type !== 'boolean' && (
                <input
                  type={type === 'date' ? 'date' : type === 'number' ? 'number' : 'text'}
                  value={Array.isArray(f.value) ? f.value.join(', ') : String(f.value ?? '')}
                  onChange={(e) =>
                    setFilter(i, {
                      ...f,
                      value: f.op === 'in' ? e.target.value.split(',').map((x) => x.trim()).filter(Boolean) : type === 'number' ? Number(e.target.value) : e.target.value,
                    })
                  }
                />
              )}
              <button className="link danger" onClick={() => setDef({ ...def, filters: def.filters.filter((_, j) => j !== i) })}>
                Entfernen
              </button>
            </div>
          );
        })}
        {source && def.filters.length < 20 && (
          <button className="link" onClick={() => setDef({ ...def, filters: [...def.filters, { field: source.columns[0]!.key, op: OPS[source.columns[0]!.type]![0]!.op, value: '' }] })}>
            + Filter
          </button>
        )}
        <p>
          <button onClick={() => void preview()}>Vorschau</button>
        </p>
      </div>

      {editable && (
        <div className="card form-inline">
          <input placeholder="Name des Berichts" value={meta.name} onChange={(e) => setMeta({ ...meta, name: e.target.value })} />
          <input placeholder="Beschreibung" value={meta.description} onChange={(e) => setMeta({ ...meta, description: e.target.value })} />
          <label className="check">
            <input type="checkbox" checked={meta.shared} onChange={(e) => setMeta({ ...meta, shared: e.target.checked })} /> mit allen Berichte-Nutzern teilen
          </label>
          <button disabled={!meta.name.trim() || !def.columns.length} onClick={() => void save()}>
            Speichern
          </button>
        </div>
      )}

      {result && (
        <>
          <p className="muted">
            {result.rows.length} Zeilen{result.truncated ? ' (Vorschau gekürzt – der Export enthält bis zu 100.000)' : ''}
          </p>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  {result.columns.map((c) => (
                    <th key={c.key}>{c.label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {result.rows.map((r, i) => (
                  <tr key={i}>
                    {result.columns.map((c) => {
                      const v = r[c.key];
                      return <td key={c.key}>{v === null || v === undefined || v === '' ? '–' : c.type === 'boolean' ? (v ? 'ja' : 'nein') : c.type === 'date' ? fmtDate(String(v)) : String(v)}</td>;
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}
