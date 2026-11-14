import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { api, unwrap } from '../api/client';
import { useAuth } from '../auth';
import { TrendChart } from '../components/TrendChart';
import { OS_LABEL } from '../format';
import { fmtDate, useLoad } from '../hooks';

const TRENDS: { key: string; title: string }[] = [
  { key: 'devices.online', title: 'Geräte online' },
  { key: 'vuln.devices_critical', title: 'Geräte mit kritischen Schwachstellen' },
  { key: 'vuln.devices_kev', title: 'Geräte mit aktiv ausgenutzten Lücken' },
  { key: 'patches.devices_security', title: 'Geräte mit offenen Sicherheitsupdates' },
  { key: 'patches.missing_total', title: 'Ausstehende Updates gesamt' },
  { key: 'tasks.failed_24h', title: 'Fehlgeschlagene Tasks (24 h)' },
  { key: 'devices.total', title: 'Geräte gesamt' },
  { key: 'licenses.overused', title: 'Überschrittene Softwarelizenzen' },
  { key: 'security.noncompliant', title: 'Geräte mit Sicherheitsproblemen' },
  { key: 'security.unencrypted', title: 'Nicht (vollständig) verschlüsselte Geräte' },
];

/** KPI tile: the label names the state – colour (left border) is never the only signal. */
function Tile({ to, value, label, sub, tone }: { to: string; value: number; label: string; sub?: ReactNode; tone?: 'critical' | 'warning' | 'ok' }) {
  const cls = tone === 'critical' && value > 0 ? 'tile sev-tile-critical' : tone === 'warning' && value > 0 ? 'tile sev-tile-medium' : tone === 'ok' ? 'tile tile-ok' : 'tile';
  return (
    <Link className={cls} to={to}>
      <span className="tile-value">{value.toLocaleString('de-DE')}</span>
      <span className="tile-label">{label}</span>
      {sub && <span className="muted small">{sub}</span>}
    </Link>
  );
}

export function Dashboard() {
  const { me } = useAuth();
  const [days, setDays] = useState(30);
  const dash = useLoad(() => unwrap(api.GET('/dashboard', { params: { query: { days } } })), [days]);
  const d = dash.data;

  return (
    <>
      <div className="toolbar">
        <h1>Übersicht</h1>
        <span className="muted">Willkommen, {me?.displayName || me?.username}</span>
        <button className="link" onClick={() => void dash.reload()}>
          Aktualisieren
        </button>
      </div>
      {dash.error && <div className="error">{dash.error}</div>}
      {!d && !dash.error && <div className="muted">Lade …</div>}
      {d && (
        <>
          <div className="tiles">
            {d.devices && (
              <Tile
                to="/devices"
                value={d.devices.total}
                label="Geräte"
                sub={
                  <>
                    {d.devices.online} online · {d.devices.stale7d} seit 7 Tagen nicht gesehen
                  </>
                }
              />
            )}
            {d.security && d.security.reported > 0 && (
              <Tile
                to="/security"
                value={d.security.noncompliant}
                label="Geräte mit Sicherheitsproblemen"
                tone="critical"
                sub={`${(d.security.encryption.unencrypted ?? 0) + (d.security.encryption.partial ?? 0)} unverschlüsselt · ${(d.security.antivirus.outdated ?? 0) + (d.security.antivirus.disabled ?? 0) + (d.security.antivirus.missing ?? 0)} Virenschutz`}
              />
            )}
            {d.vulnerabilities && <Tile to="/vulnerabilities" value={d.vulnerabilities.devicesKev} label="Geräte mit aktiv ausgenutzten Lücken" tone="critical" sub="CISA KEV" />}
            {d.vulnerabilities && <Tile to="/vulnerabilities" value={d.vulnerabilities.devicesCritical} label="Geräte mit kritischen Schwachstellen" tone="critical" sub={`${d.vulnerabilities.findingsOpen} offene Befunde`} />}
            {d.patches && <Tile to="/patches" value={d.patches.devicesSecurity} label="Geräte mit Sicherheitsupdates" tone="warning" sub={`${d.patches.missingTotal} Updates ausstehend · ${d.patches.rebootPending} Neustarts`} />}
            {d.tasks && <Tile to="/runs" value={d.tasks.failed24h} label="Fehlgeschlagene Tasks (24 h)" tone="warning" />}
            {d.integrity && <Tile to="/audit" value={d.integrity.violations7d} label="Hash-Prüfung fehlgeschlagen (7 Tage)" tone="critical" sub="Manipulationsverdacht" />}
            {d.deployments && <Tile to="/deployments" value={d.deployments.running} label="Laufende Verteilungen" sub={`${d.deployments.paused} angehalten`} tone={d.deployments.paused ? 'warning' : undefined} />}
            {d.licenses && d.licenses.total > 0 && <Tile to="/licenses" value={d.licenses.overused} label="Softwarelizenzen überschritten" tone="warning" sub={`${d.licenses.expiringSoon} laufen bald ab`} />}
            {d.assets && d.assets.total > 0 && (
              <Tile to="/assets" value={d.assets.warrantyExpiring30d} label="Asset-Garantien laufen in 30 Tagen ab" tone="warning" sub={`${d.assets.total} Assets · ${d.assets.warrantyExpired} Garantie abgelaufen`} />
            )}
          </div>

          {d.devices && Object.keys(d.devices.byOs).length > 0 && (
            <div className="card">
              <h2>Geräte nach Betriebssystem</h2>
              <div className="bars">
                {Object.entries(d.devices.byOs)
                  .sort((a, b) => b[1] - a[1])
                  .map(([os, n]) => (
                    <div key={os} className="bar-row" title={`${OS_LABEL[os] ?? os}: ${n}`}>
                      <span className="bar-label">{OS_LABEL[os] ?? os}</span>
                      <span className="bar-track">
                        <span className="bar-fill" style={{ width: `${(n / Math.max(...Object.values(d.devices!.byOs), 1)) * 100}%` }} />
                      </span>
                      <span className="bar-value">{n}</span>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {Object.keys(d.trends).length > 0 && (
            <>
              <div className="toolbar">
                <h2>Verlauf</h2>
                <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
                  <option value={30}>30 Tage</option>
                  <option value={90}>90 Tage</option>
                  <option value={365}>1 Jahr</option>
                </select>
              </div>
              <div className="trends">
                {TRENDS.filter((t) => d.trends[t.key]).map((t) => (
                  <TrendChart key={t.key} title={t.title} points={d.trends[t.key]!} />
                ))}
              </div>
              <p className="muted small">Tageswerte werden stündlich aktualisiert. Stand: {fmtDate(d.generatedAt)}</p>
            </>
          )}
        </>
      )}
    </>
  );
}
