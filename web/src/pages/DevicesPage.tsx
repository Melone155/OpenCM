import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, unwrap } from '../api/client';
import { useAuth } from '../auth';
import { fmtRelative, OS_LABEL } from '../format';
import { useLoad } from '../hooks';

const PAGE = 100;

export function DevicesPage() {
  const { can } = useAuth();
  const [search, setSearch] = useState('');
  const [os, setOs] = useState<'' | 'windows' | 'linux' | 'macos'>('');
  const [online, setOnline] = useState<'' | 'true' | 'false'>('');
  const [offset, setOffset] = useState(0);
  const devices = useLoad(
    () =>
      unwrap(
        api.GET('/devices', {
          params: { query: { search: search || undefined, os: os || undefined, online: online || undefined, limit: PAGE, offset } },
        }),
      ),
    [search, os, online, offset],
  );

  const reset = <T,>(set: (v: T) => void) => (v: T) => {
    set(v);
    setOffset(0);
  };

  return (
    <>
      <div className="toolbar">
        <h1>Geräte</h1>
        <input placeholder="Hostname, Seriennr., Benutzer …" value={search} onChange={(e) => reset(setSearch)(e.target.value)} />
        <select value={os} onChange={(e) => reset(setOs)(e.target.value as typeof os)}>
          <option value="">Alle Betriebssysteme</option>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
          <option value="macos">macOS</option>
        </select>
        <select value={online} onChange={(e) => reset(setOnline)(e.target.value as typeof online)}>
          <option value="">Online & offline</option>
          <option value="true">Nur online</option>
          <option value="false">Nur offline</option>
        </select>
        {can('devices:create') && (
          <Link className="button" to="/enrollment">
            Geräte hinzufügen
          </Link>
        )}
      </div>
      {devices.error && <div className="error">{devices.error}</div>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Hostname</th>
              <th>Betriebssystem</th>
              <th>Hersteller / Modell</th>
              <th>Angemeldet</th>
              <th>Letzter Kontakt</th>
              <th>Agent</th>
            </tr>
          </thead>
          <tbody>
            {devices.data?.items.map((d) => (
              <tr key={d.id}>
                <td>
                  {d.status === 'revoked' ? (
                    <span className="badge danger">widerrufen</span>
                  ) : d.online ? (
                    <span className="badge ok">online</span>
                  ) : (
                    <span className="badge">offline</span>
                  )}
                </td>
                <td>
                  <Link to={`/devices/${d.id}`}>{d.hostname}</Link>
                </td>
                <td>
                  {OS_LABEL[d.os]} <span className="muted">{d.osVersion}</span>
                </td>
                <td>{[d.manufacturer, d.model].filter(Boolean).join(' ') || '–'}</td>
                <td>{d.loggedOnUser ?? '–'}</td>
                <td title={d.lastSeenAt ?? ''}>{fmtRelative(d.lastSeenAt)}</td>
                <td className="muted">{d.agentVersion ?? '–'}</td>
              </tr>
            ))}
            {devices.data && devices.data.items.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">
                  Keine Geräte gefunden.{can('devices:create') && <> Neue Geräte über „Geräte hinzufügen“ registrieren.</>}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {devices.data && devices.data.total > PAGE && (
        <div className="pager">
          <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
            Zurück
          </button>
          <span className="muted">
            {offset + 1}–{Math.min(offset + PAGE, devices.data.total)} von {devices.data.total}
          </span>
          <button disabled={offset + PAGE >= devices.data.total} onClick={() => setOffset(offset + PAGE)}>
            Weiter
          </button>
        </div>
      )}
      {devices.data && <div className="muted">{devices.data.total} Geräte</div>}
    </>
  );
}
