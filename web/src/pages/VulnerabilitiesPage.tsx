import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, unwrap } from '../api/client';
import { useAuth } from '../auth';
import { fmtRelative } from '../format';
import { useLoad } from '../hooks';

export const SEV_LABEL: Record<string, string> = { CRITICAL: 'kritisch', HIGH: 'hoch', MEDIUM: 'mittel', LOW: 'niedrig', NONE: 'keine' };
export const CONF_LABEL: Record<string, string> = { high: 'sicher', medium: 'wahrscheinlich', low: 'unbestätigt' };
export const CONF_HINT: Record<string, string> = {
  high: 'Zuordnung über Regel',
  medium: 'Zuordnung über Namensheuristik',
  low: 'Distributions-Paket – der Fix kann zurückportiert sein, ohne dass sich die Version ändert',
};
/** Explanation of a finding's confidence; OSV findings come from the distribution's own advisory. */
export const confHint = (confidence: string, vendor?: string) =>
  vendor === 'osv' ? 'Sicherheitsmeldung der Linux-Distribution (OSV) – exakte Paketversion, Backports berücksichtigt' : CONF_HINT[confidence];
const FEED_LABEL: Record<string, string> = {
  nvd: 'NVD (CVE-Datenbank)',
  kev: 'CISA KEV (aktiv ausgenutzt)',
  epss: 'FIRST EPSS (Ausnutzungswahrscheinlichkeit)',
  osv: 'OSV (Linux-Distributionspakete)',
  evaluation: 'Bewertung der Geräte',
};

export function SeverityBadge({ severity, score }: { severity: string | null | undefined; score?: number | null }) {
  const s = severity ?? 'NONE';
  return (
    <span className={`sev sev-${s.toLowerCase()}`}>
      {SEV_LABEL[s] ?? s}
      {score !== undefined && score !== null && ` ${score.toFixed(1)}`}
    </span>
  );
}

export function KevBadge({ kev }: { kev: boolean }) {
  return kev ? (
    <span className="badge danger" title="In CISA Known Exploited Vulnerabilities gelistet: wird aktiv ausgenutzt">
      aktiv ausgenutzt
    </span>
  ) : null;
}

export const pct = (v: number | null | undefined) => (v === null || v === undefined ? '–' : `${(v * 100).toFixed(v < 0.01 ? 2 : 1)} %`);

const PAGE = 100;

export function VulnerabilitiesPage() {
  const { can } = useAuth();
  const [severity, setSeverity] = useState<string[]>([]);
  const [kev, setKev] = useState(false);
  const [confidence, setConfidence] = useState<string>('');
  const [search, setSearch] = useState('');
  const [includeAccepted, setIncludeAccepted] = useState(false);
  const [offset, setOffset] = useState(0);
  const [msg, setMsg] = useState<string | null>(null);
  const summary = useLoad(() => unwrap(api.GET('/vulnerabilities/summary')));
  const list = useLoad(
    () =>
      unwrap(
        api.GET('/vulnerabilities', {
          params: {
            query: {
              severity: severity.join(',') || undefined,
              kev: kev ? 'true' : undefined,
              confidence: confidence || undefined,
              search: search || undefined,
              includeAccepted: includeAccepted ? 'true' : 'false',
              limit: PAGE,
              offset,
            },
          },
        }),
      ),
    [severity, kev, confidence, search, includeAccepted, offset],
  );
  const s = summary.data;
  const toggleSev = (v: string) => {
    setSeverity(severity.includes(v) ? severity.filter((x) => x !== v) : [...severity, v]);
    setOffset(0);
  };
  const nvd = s?.feeds.find((f) => f.name === 'nvd');
  const mirrorIncomplete = !nvd?.lastSuccessAt;

  return (
    <>
      <div className="toolbar">
        <h1>Schwachstellen</h1>
        <Link to="/software" className="muted">
          Software &amp; Zuordnung
        </Link>
        {can('vulnerabilities:update') && (
          <button
            className="link"
            onClick={() =>
              void unwrap(api.POST('/vulnerability-feeds/sync', { body: {} }))
                .then(() => setMsg('Synchronisation angefordert – der Worker startet sie innerhalb einer Minute.'))
                .catch((e: Error) => setMsg(e.message))
            }
          >
            Jetzt synchronisieren
          </button>
        )}
      </div>
      {msg && <div className="card">{msg}</div>}
      {s && mirrorIncomplete && (
        <div className="card highlight">
          Der NVD-Spiegel wird gerade aufgebaut{nvd?.stats && typeof nvd.stats.startIndex === 'number' ? ` (${(nvd.stats.startIndex as number).toLocaleString('de-DE')} CVEs geladen)` : ''}. Bis er
          vollständig ist, können Befunde fehlen.
        </div>
      )}

      {s && (
        <div className="tiles">
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((k) => (
            <button key={k} className={`tile sev-tile-${k.toLowerCase()} ${severity.includes(k) ? 'active' : ''}`} onClick={() => toggleSev(k)}>
              <span className="tile-value">{s.bySeverity[k]?.cves ?? 0}</span>
              <span className="tile-label">{SEV_LABEL[k]}</span>
              <span className="muted small">{s.bySeverity[k]?.devices ?? 0} Geräte</span>
            </button>
          ))}
          <button className={`tile tile-kev ${kev ? 'active' : ''}`} onClick={() => { setKev(!kev); setOffset(0); }}>
            <span className="tile-value">{s.kev.cves}</span>
            <span className="tile-label">aktiv ausgenutzt</span>
            <span className="muted small">{s.kev.overdue > 0 ? `${s.kev.overdue} überfällig (CISA-Frist)` : `${s.kev.devices} Geräte`}</span>
          </button>
          <div className="tile">
            <span className="tile-value">{s.affectedDevices}</span>
            <span className="tile-label">betroffene Geräte</span>
            <span className="muted small">{s.openFindings} Befunde</span>
          </div>
        </div>
      )}

      <div className="toolbar">
        <input
          placeholder="CVE, Produkt, Software …"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setOffset(0);
          }}
        />
        <select value={confidence} onChange={(e) => { setConfidence(e.target.value); setOffset(0); }}>
          <option value="">alle Zuordnungen</option>
          <option value="high,medium">nur sicher / wahrscheinlich</option>
          <option value="high">nur sicher (Regel)</option>
          <option value="low">nur unbestätigt (Distributions-Pakete)</option>
        </select>
        <label className="check">
          <input type="checkbox" checked={includeAccepted} onChange={(e) => setIncludeAccepted(e.target.checked)} />
          akzeptierte Risiken zeigen
        </label>
      </div>

      {list.error && <div className="error">{list.error}</div>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>CVE</th>
              <th>Schweregrad</th>
              <th>EPSS</th>
              <th>Produkt</th>
              <th>Geräte</th>
              <th>Zuordnung</th>
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((v) => (
              <tr key={v.cveId}>
                <td>
                  <Link to={`/vulnerabilities/${v.cveId}`}>{v.cveId}</Link> <KevBadge kev={v.kev} />
                  {v.acceptedAt && <span className="badge">akzeptiert</span>}
                  <div className="muted small clamp">{v.description}</div>
                </td>
                <td>
                  <SeverityBadge severity={v.cvssSeverity} score={v.cvssScore} />
                </td>
                <td title={v.epssPercentile ? `Perzentil ${pct(v.epssPercentile)}` : ''}>{pct(v.epss)}</td>
                <td className="perms">{v.products.join(', ')}</td>
                <td>{v.affectedDevices}</td>
                <td title={CONF_HINT[v.confidence]}>{CONF_LABEL[v.confidence]}</td>
              </tr>
            ))}
            {list.data?.items.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  Keine offenen Schwachstellen für diese Auswahl.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {list.data && list.data.total > PAGE && (
        <div className="pager">
          <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
            Zurück
          </button>
          <span className="muted">
            {offset + 1}–{Math.min(offset + PAGE, list.data.total)} von {list.data.total}
          </span>
          <button disabled={offset + PAGE >= list.data.total} onClick={() => setOffset(offset + PAGE)}>
            Weiter
          </button>
        </div>
      )}

      {s && (
        <details className="card">
          <summary>Feeds: {s.mirror.cves.toLocaleString('de-DE')} CVEs im Spiegel, {s.mirror.kev} KEV</summary>
          <table>
            <thead>
              <tr>
                <th>Feed</th>
                <th>Zuletzt erfolgreich</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {s.feeds.map((f) => (
                <tr key={f.name}>
                  <td>{FEED_LABEL[f.name] ?? f.name.toUpperCase()}</td>
                  <td>{fmtRelative(f.lastSuccessAt)}</td>
                  <td>{f.running ? 'läuft …' : f.error ? <span className="error-text">{f.error}</span> : 'ok'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </>
  );
}
