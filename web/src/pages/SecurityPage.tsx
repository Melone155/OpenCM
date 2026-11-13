import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { api, jsonOnly, unwrap, type Schemas } from '../api/client';
import { fmtRelative, OS_LABEL } from '../format';
import { fmtDate, useLoad } from '../hooks';

type Row = Schemas['DeviceSecurityRow'];

export const ENCRYPTION_LABEL: Record<string, string> = { encrypted: 'verschlüsselt', partial: 'teilweise', unencrypted: 'unverschlüsselt', unknown: 'unbekannt' };
export const ANTIVIRUS_LABEL: Record<string, string> = { ok: 'aktiv & aktuell', outdated: 'veraltet', disabled: 'deaktiviert', missing: 'fehlt', unknown: 'unbekannt' };
export const FIREWALL_LABEL: Record<string, string> = { on: 'an', partial: 'teilweise', off: 'aus', unknown: 'unbekannt' };
const TPM_LABEL: Record<string, string> = { ready: 'bereit', present: 'vorhanden (nicht bereit)', missing: 'fehlt', unknown: 'unbekannt' };

const GOOD = new Set(['encrypted', 'ok', 'on', 'ready']);
const BAD = new Set(['unencrypted', 'disabled', 'missing', 'off']);

/** State with text – the colour of the badge is never the only signal. */
function State({ value, labels }: { value: string; labels: Record<string, string> }) {
  const cls = GOOD.has(value) ? 'badge ok' : BAD.has(value) ? 'badge danger' : value === 'unknown' ? 'badge' : 'badge warn';
  return <span className={cls}>{labels[value] ?? value}</span>;
}

function Compliance({ row }: { row: Pick<Row, 'reported' | 'compliant'> }) {
  if (!row.reported) return <span className="badge">keine Daten</span>;
  return row.compliant ? <span className="badge ok">konform</span> : <span className="badge danger">nicht konform</span>;
}

const yesNo = (v: boolean | null | undefined) => (v === null || v === undefined ? '–' : v ? 'ja' : 'nein');

type Filters = { search: string; os: string; compliant: string; reported: string; encryption: string; antivirus: string; firewall: string; issue: string };
const NO_FILTERS: Filters = { search: '', os: '', compliant: '', reported: '', encryption: '', antivirus: '', firewall: '', issue: '' };

/** Fleet security status: disk encryption, antivirus, firewall, Secure Boot, TPM. */
export function SecurityPage() {
  const [f, setF] = useState<Filters>(NO_FILTERS);
  const [offset, setOffset] = useState(0);
  const limit = 100;
  const query = Object.fromEntries(Object.entries(f).filter(([, v]) => v));
  const list = useLoad(() => jsonOnly(unwrap(api.GET('/security-status', { params: { query: { ...(query as Record<string, never>), limit, offset } } }))), [JSON.stringify(f), offset]);
  const s = list.data?.summary;
  const set = (patch: Partial<Filters>) => {
    setF({ ...f, ...patch });
    setOffset(0);
  };
  const tile = (active: boolean, onClick: () => void, value: number, label: string, sub: ReactNode, tone: string) => (
    <button className={`tile ${tone} ${active ? 'active' : ''}`} aria-pressed={active} onClick={onClick}>
      <span className="tile-value">{value.toLocaleString('de-DE')}</span>
      <span className="tile-label">{label}</span>
      <span className="muted small">{sub}</span>
    </button>
  );
  const csvHref = `/api/v1/security-status?${new URLSearchParams({ ...(query as Record<string, string>), format: 'csv' })}`;

  return (
    <>
      <div className="toolbar">
        <h1>Sicherheitsstatus</h1>
        <a className="button" href={csvHref}>
          CSV exportieren
        </a>
      </div>
      <p className="muted">
        Der Agent meldet mit jedem Inventar Festplattenverschlüsselung (BitLocker, FileVault, LUKS), Virenschutz (Microsoft Defender, andere Produkte, XProtect), Firewall, Secure Boot und TPM. Ein Gerät ist <strong>konform</strong>, wenn seine
        Laufwerke verschlüsselt sind, die Firewall an ist und – unter Windows und macOS – ein aktueller Virenschutz läuft.
      </p>
      {list.error && <div className="error">{list.error}</div>}
      {s && (
        <div className="tiles">
          {tile(f.compliant === 'false', () => set({ ...NO_FILTERS, compliant: f.compliant === 'false' ? '' : 'false' }), s.noncompliant, 'Nicht konform', `von ${s.reported} Geräten mit Daten`, 'sev-tile-critical')}
          {tile(f.compliant === 'true', () => set({ ...NO_FILTERS, compliant: f.compliant === 'true' ? '' : 'true' }), s.compliant, 'Konform', `${s.devices ? Math.round((s.compliant / s.devices) * 100) : 0} % aller Geräte`, 'tile-ok')}
          {tile(
            f.encryption === 'unencrypted',
            () => set({ ...NO_FILTERS, encryption: f.encryption === 'unencrypted' ? '' : 'unencrypted' }),
            (s.encryption.unencrypted ?? 0) + (s.encryption.partial ?? 0),
            'Nicht (vollständig) verschlüsselt',
            `${s.encryption.partial ?? 0} teilweise`,
            'sev-tile-high',
          )}
          {tile(
            f.antivirus !== '',
            () => set({ ...NO_FILTERS, antivirus: f.antivirus ? '' : 'outdated' }),
            (s.antivirus.outdated ?? 0) + (s.antivirus.disabled ?? 0) + (s.antivirus.missing ?? 0),
            'Virenschutz-Probleme',
            `${s.antivirus.outdated ?? 0} veraltet · ${s.antivirus.disabled ?? 0} aus · ${s.antivirus.missing ?? 0} fehlt`,
            'sev-tile-medium',
          )}
          {tile(f.firewall === 'off', () => set({ ...NO_FILTERS, firewall: f.firewall === 'off' ? '' : 'off' }), (s.firewall.off ?? 0) + (s.firewall.partial ?? 0), 'Firewall aus', `${s.firewall.partial ?? 0} teilweise`, 'sev-tile-medium')}
          {tile(f.reported === 'false', () => set({ ...NO_FILTERS, reported: f.reported === 'false' ? '' : 'false' }), s.devices - s.reported, 'Ohne Daten', 'Agent älter als 0.8 oder noch kein Inventar', '')}
        </div>
      )}

      <div className="form-inline">
        <input placeholder="Gerät oder Benutzer …" value={f.search} onChange={(e) => set({ search: e.target.value })} />
        <select value={f.os} onChange={(e) => set({ os: e.target.value })} aria-label="Betriebssystem">
          <option value="">Alle Betriebssysteme</option>
          {Object.entries(OS_LABEL).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
        <select value={f.encryption} onChange={(e) => set({ encryption: e.target.value })} aria-label="Verschlüsselung">
          <option value="">Verschlüsselung: alle</option>
          {Object.entries(ENCRYPTION_LABEL).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
        <select value={f.antivirus} onChange={(e) => set({ antivirus: e.target.value })} aria-label="Virenschutz">
          <option value="">Virenschutz: alle</option>
          {Object.entries(ANTIVIRUS_LABEL).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
        <select value={f.firewall} onChange={(e) => set({ firewall: e.target.value })} aria-label="Firewall">
          <option value="">Firewall: alle</option>
          {Object.entries(FIREWALL_LABEL).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
        {list.data && (
          <select value={f.issue} onChange={(e) => set({ issue: e.target.value })} aria-label="Problem">
            <option value="">Problem: alle</option>
            {Object.entries(list.data.issueLabels).map(([k, v]) => (
              <option key={k} value={k}>
                {v} {s?.issues[k] ? `(${s.issues[k]})` : ''}
              </option>
            ))}
          </select>
        )}
        {JSON.stringify(f) !== JSON.stringify(NO_FILTERS) && (
          <button className="link" onClick={() => set(NO_FILTERS)}>
            Filter zurücksetzen
          </button>
        )}
      </div>

      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Gerät</th>
              <th>Status</th>
              <th>Verschlüsselung</th>
              <th>Virenschutz</th>
              <th>Firewall</th>
              <th>Secure Boot</th>
              <th>Probleme</th>
              <th>Erfasst</th>
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((r) => (
              <tr key={r.deviceId}>
                <td>
                  <Link to={`/devices/${r.deviceId}`} state={{ tab: 'Sicherheit' }}>
                    {r.hostname}
                  </Link>
                  <div className="muted small">{OS_LABEL[r.os] ?? r.os}</div>
                </td>
                <td>
                  <Compliance row={r} />
                </td>
                <td>{r.reported ? <State value={r.encryption} labels={ENCRYPTION_LABEL} /> : '–'}</td>
                <td>{r.reported ? <State value={r.antivirus} labels={ANTIVIRUS_LABEL} /> : '–'}</td>
                <td>{r.reported ? <State value={r.firewall} labels={FIREWALL_LABEL} /> : '–'}</td>
                <td>{yesNo(r.secureBoot)}</td>
                <td className="perms">{r.issues.map((i) => i.label).join(' · ') || '–'}</td>
                <td className="muted small">{r.collectedAt ? fmtRelative(r.collectedAt) : '–'}</td>
              </tr>
            ))}
            {list.data?.items.length === 0 && (
              <tr>
                <td colSpan={8} className="muted">
                  Keine Geräte für diese Auswahl.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {list.data && list.data.total > limit && (
        <div className="pager">
          <button className="link" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>
            ← zurück
          </button>
          <span className="muted">
            {offset + 1}–{Math.min(offset + limit, list.data.total)} von {list.data.total}
          </span>
          <button className="link" disabled={offset + limit >= list.data.total} onClick={() => setOffset(offset + limit)}>
            weiter →
          </button>
        </div>
      )}
    </>
  );
}

/** "Sicherheit" tab on the device page. */
export function DeviceSecurityTab({ deviceId }: { deviceId: string }) {
  const sec = useLoad(
    () =>
      api.GET('/devices/{id}/security', { params: { path: { id: deviceId } } }).then((r) => {
        if (r.response.status === 404) return null;
        if (r.error) throw new Error((r.error as Schemas['Error']).error.message);
        return r.data ?? null;
      }),
    [deviceId],
  );
  if (sec.error) return <div className="error">{sec.error}</div>;
  if (sec.data === undefined) return <div className="muted">Lade …</div>;
  if (sec.data === null) return <p className="muted">Für dieses Gerät liegt noch kein Sicherheitsstatus vor. Er wird ab Agent-Version 0.8 mit jedem Inventar gemeldet.</p>;
  const s = sec.data;
  const d = s.details;
  return (
    <>
      <div className="card">
        <div className="toolbar">
          <h2>
            Gesamt: <Compliance row={{ reported: true, compliant: s.compliant }} />
          </h2>
          <span className="muted small">Erfasst {fmtDate(s.collectedAt)}</span>
        </div>
        {s.issues.length > 0 ? (
          <ul className="plain">
            {s.issues.map((i) => (
              <li key={i.code}>
                <span className="badge danger">!</span> {i.label}
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted">Keine Probleme gefunden.</p>
        )}
      </div>

      <div className="grid2">
        <div className="card">
          <h2>
            Verschlüsselung <State value={s.encryption} labels={ENCRYPTION_LABEL} />
          </h2>
          <p className="muted small">{d.encryption?.product ?? 'Produkt unbekannt'}</p>
          <table>
            <thead>
              <tr>
                <th>Laufwerk</th>
                <th>Verschlüsselt</th>
                <th>Status</th>
                <th>Schutz</th>
              </tr>
            </thead>
            <tbody>
              {(d.encryption?.volumes ?? []).map((v) => (
                <tr key={v.volume}>
                  <td>
                    {v.volume} {v.system && <span className="badge">System</span>}
                  </td>
                  <td>{yesNo(v.encrypted)}</td>
                  <td className="muted small">
                    {v.status ?? '–'}
                    {v.method ? ` · ${v.method}` : ''}
                  </td>
                  <td>{v.protection === false ? <span className="badge danger">angehalten</span> : yesNo(v.protection)}</td>
                </tr>
              ))}
              {!(d.encryption?.volumes ?? []).length && (
                <tr>
                  <td colSpan={4} className="muted">
                    Keine Angaben (fehlende Rechte oder Funktion nicht installiert).
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="card">
          <h2>
            Virenschutz <State value={s.antivirus} labels={ANTIVIRUS_LABEL} />
          </h2>
          <table>
            <thead>
              <tr>
                <th>Produkt</th>
                <th>Aktiv</th>
                <th>Echtzeit</th>
                <th>Signaturen</th>
              </tr>
            </thead>
            <tbody>
              {(d.antivirus ?? []).map((a) => (
                <tr key={a.name}>
                  <td>{a.name}</td>
                  <td>{yesNo(a.enabled)}</td>
                  <td>{yesNo(a.realtime)}</td>
                  <td className="small">
                    {a.signatureVersion ?? ''}
                    {a.signatureUpdatedAt && <div className="muted">{fmtRelative(a.signatureUpdatedAt)}</div>}
                    {a.upToDate === false && <span className="badge warn">veraltet</span>}
                  </td>
                </tr>
              ))}
              {!(d.antivirus ?? []).length && (
                <tr>
                  <td colSpan={4} className="muted">
                    Kein Virenschutz gemeldet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="card">
          <h2>
            Firewall <State value={s.firewall} labels={FIREWALL_LABEL} />
          </h2>
          <p className="muted small">{d.firewall?.product ?? ''}</p>
          {(d.firewall?.profiles ?? []).length > 0 ? (
            <ul className="plain">
              {(d.firewall?.profiles ?? []).map((p) => (
                <li key={p.name}>
                  {p.name}: <strong>{p.enabled === null || p.enabled === undefined ? 'unbekannt' : p.enabled ? 'an' : 'aus'}</strong>
                </li>
              ))}
            </ul>
          ) : (
            <p>{d.firewall?.enabled === null || d.firewall?.enabled === undefined ? 'unbekannt' : d.firewall.enabled ? 'an' : 'aus'}</p>
          )}
        </div>

        <div className="card">
          <h2>Plattform</h2>
          <dl className="facts">
            <div>
              <dt>Secure Boot</dt>
              <dd>{yesNo(s.secureBoot)}</dd>
            </div>
            <div>
              <dt>TPM</dt>
              <dd>
                {TPM_LABEL[s.tpm] ?? s.tpm}
                {d.tpm?.version ? ` (Version ${d.tpm.version})` : ''}
              </dd>
            </div>
          </dl>
        </div>
      </div>
    </>
  );
}
