import { useState } from 'react';
import { api, unwrap } from '../api/client';
import { useAuth } from '../auth';
import { useLoad } from '../hooks';
import { CONF_LABEL } from './VulnerabilitiesPage';
import { DeleteButton } from './UsersPage';

const PAGE = 100;

export function SoftwarePage() {
  const { can } = useAuth();
  const [search, setSearch] = useState('');
  const [mapping, setMapping] = useState<'all' | 'mapped' | 'unmapped' | 'ignored'>('all');
  const [offset, setOffset] = useState(0);
  const [rule, setRule] = useState<{ namePattern: string; vendor: string; product: string; ignore: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const sw = useLoad(() => unwrap(api.GET('/software', { params: { query: { search: search || undefined, mapping, limit: PAGE, offset } } })), [search, mapping, offset]);

  async function saveRule() {
    if (!rule) return;
    setError(null);
    try {
      await unwrap(
        api.POST('/cpe-rules', {
          body: rule.ignore ? { namePattern: rule.namePattern, ignore: true } : { namePattern: rule.namePattern, vendor: rule.vendor, product: rule.product },
        }),
      );
      setRule(null);
      setMsg('Regel gespeichert. Die Befunde werden mit dem nächsten Worker-Lauf neu bewertet.');
      await sw.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <>
      <div className="toolbar">
        <h1>Software im Bestand</h1>
        <input placeholder="Name oder Hersteller …" value={search} onChange={(e) => { setSearch(e.target.value); setOffset(0); }} />
        <select value={mapping} onChange={(e) => { setMapping(e.target.value as typeof mapping); setOffset(0); }}>
          <option value="all">alle</option>
          <option value="mapped">mit CPE-Zuordnung</option>
          <option value="unmapped">ohne Zuordnung</option>
          <option value="ignored">ignoriert</option>
        </select>
      </div>
      <p className="muted">
        Für die Schwachstellenerkennung wird jede Software einem CPE-Produkt aus der NVD zugeordnet: zuerst über Regeln, dann per Namensheuristik. Software ohne Zuordnung wird nicht
        geprüft. Mit einer Regel lässt sich die Zuordnung korrigieren oder Software ignorieren.
      </p>
      {msg && <div className="card">{msg}</div>}
      {error && <div className="error">{error}</div>}
      {rule && (
        <div className="card highlight form-inline">
          <input value={rule.namePattern} onChange={(e) => setRule({ ...rule, namePattern: e.target.value })} title="Muster mit * und ?" />
          <label className="check">
            <input type="checkbox" checked={rule.ignore} onChange={(e) => setRule({ ...rule, ignore: e.target.checked })} />
            ignorieren
          </label>
          {!rule.ignore && (
            <>
              <input placeholder="vendor" value={rule.vendor} onChange={(e) => setRule({ ...rule, vendor: e.target.value })} />
              <input placeholder="product" value={rule.product} onChange={(e) => setRule({ ...rule, product: e.target.value })} />
            </>
          )}
          <button onClick={() => void saveRule()}>Regel speichern</button>
          <button className="link" onClick={() => setRule(null)}>
            Abbrechen
          </button>
        </div>
      )}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Software</th>
              <th>Hersteller</th>
              <th>Quelle</th>
              <th>Geräte</th>
              <th>Versionen</th>
              <th>CPE-Zuordnung</th>
            </tr>
          </thead>
          <tbody>
            {sw.data?.items.map((s) => (
              <tr key={`${s.name}|${s.publisher}|${s.source}`}>
                <td>{s.name}</td>
                <td>{s.publisher || '–'}</td>
                <td className="muted">{s.source}</td>
                <td>{s.deviceCount}</td>
                <td className="perms">{s.versions.join(', ')}</td>
                <td>
                  {s.mapping && 'ignored' in s.mapping ? (
                    <span className="badge">ignoriert</span>
                  ) : s.mapping ? (
                    <>
                      <code>
                        {s.mapping.vendor}:{s.mapping.product}
                      </code>{' '}
                      <span className="muted small">
                        {s.mapping.method === 'rule' ? 'Regel' : 'Heuristik'}, {CONF_LABEL[s.mapping.confidence]}
                      </span>
                    </>
                  ) : (
                    <span className="muted">–</span>
                  )}
                  {can('vulnerabilities:update') && (
                    <div className="small">
                      {s.suggestions.map((g) => (
                        <button key={`${g.vendor}:${g.product}`} className="link" onClick={() => setRule({ namePattern: `${s.name}*`, vendor: g.vendor, product: g.product, ignore: false })}>
                          → {g.vendor}:{g.product}
                        </button>
                      ))}
                      <button className="link" onClick={() => setRule({ namePattern: s.name, vendor: '', product: '', ignore: !s.mapping })}>
                        Regel …
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {sw.data && (
        <div className="pager">
          <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
            Zurück
          </button>
          <span className="muted">{sw.data.total} Einträge</span>
          <button disabled={offset + PAGE >= sw.data.total} onClick={() => setOffset(offset + PAGE)}>
            Weiter
          </button>
        </div>
      )}
      <CpeRules />
    </>
  );
}

function CpeRules() {
  const { can } = useAuth();
  const rules = useLoad(() => unwrap(api.GET('/cpe-rules')));
  const [showBuiltin, setShowBuiltin] = useState(false);
  const items = (rules.data?.items ?? []).filter((r) => showBuiltin || r.origin === 'user');
  return (
    <details className="card" open>
      <summary>Zuordnungsregeln ({rules.data?.items.filter((r) => r.origin === 'user').length ?? 0} eigene)</summary>
      <label className="check">
        <input type="checkbox" checked={showBuiltin} onChange={(e) => setShowBuiltin(e.target.checked)} />
        mitgelieferte Regeln anzeigen
      </label>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Muster</th>
              <th>Quelle</th>
              <th>Ergebnis</th>
              <th>Priorität</th>
              <th>Herkunft</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {items.map((r) => (
              <tr key={r.id} className={r.enabled ? undefined : 'muted'}>
                <td>
                  <code>{r.namePattern}</code>
                  {r.note && <div className="muted small">{r.note}</div>}
                </td>
                <td>{r.source ?? 'alle'}</td>
                <td>{r.ignore ? 'ignorieren' : <code>{`${r.vendor}:${r.product}`}</code>}</td>
                <td>{r.priority}</td>
                <td>{r.origin === 'builtin' ? 'mitgeliefert' : 'eigene'}</td>
                <td className="actions">
                  {can('vulnerabilities:update') && (
                    <button className="link" onClick={() => void unwrap(api.PATCH('/cpe-rules/{id}', { params: { path: { id: r.id } }, body: { enabled: !r.enabled } })).then(() => rules.reload())}>
                      {r.enabled ? 'deaktivieren' : 'aktivieren'}
                    </button>
                  )}
                  {can('vulnerabilities:update') && r.origin === 'user' && (
                    <DeleteButton onConfirm={() => unwrap(api.DELETE('/cpe-rules/{id}', { params: { path: { id: r.id } } })).then(() => rules.reload())} />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
