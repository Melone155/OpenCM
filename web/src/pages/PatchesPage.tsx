import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api, unwrap } from '../api/client';
import { useAuth } from '../auth';
import { DEFAULT_RINGS, emptyTargets, hasTargets, RingsEditor, TargetPicker, type Ring, type Targets } from '../components/Rings';
import { fmtDate, useLoad } from '../hooks';
import { startDeployment } from './DeploymentsPage';

type Filter = 'all' | 'missing' | 'security' | 'reboot' | 'never' | 'failed';
const SOURCE_LABEL: Record<string, string> = { windows_update: 'Windows Update', apt: 'apt', dnf: 'dnf', softwareupdate: 'macOS' };

export function PatchesPage() {
  const { can, canScoped } = useAuth();
  const summary = useLoad(() => unwrap(api.GET('/patches/summary')));
  const [tab, setTab] = useState<'devices' | 'updates'>('devices');
  const [filter, setFilter] = useState<Filter>('all');
  const [panel, setPanel] = useState<'scan' | 'install' | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const s = summary.data;

  const tile = (f: Filter, label: string, n: number | undefined, cls = '') => (
    <button className={`tile ${cls} ${filter === f && tab === 'devices' ? 'active' : ''}`} onClick={() => { setTab('devices'); setFilter(filter === f ? 'all' : f); }}>
      <span className="tile-value">{n ?? '…'}</span>
      <span className="tile-label">{label}</span>
    </button>
  );

  return (
    <>
      <div className="toolbar">
        <h1>Patches</h1>
        {canScoped('patches:execute') && (
          <button className="link" onClick={() => setPanel(panel === 'scan' ? null : 'scan')}>
            Jetzt scannen …
          </button>
        )}
        {can('patches:execute') && <button onClick={() => setPanel(panel === 'install' ? null : 'install')}>Updates installieren …</button>}
        <a className="button link" href="/api/v1/patches/export?format=csv">
          Export CSV
        </a>
      </div>
      {s && (
        <p className="muted">
          {s.scanned} von {s.devices} Geräten gescannt · automatischer Scan {s.scanIntervalHours > 0 ? `alle ${s.scanIntervalHours} h` : 'aus'} · {s.missingTotal} ausstehende Updates, davon {s.securityTotal} Sicherheit
        </p>
      )}
      {panel === 'scan' && <ScanPanel onDone={() => { setPanel(null); void summary.reload(); }} />}
      {panel === 'install' && <InstallPanel include={selected} onCancel={() => setPanel(null)} />}
      <div className="tiles">
        {tile('all', 'Geräte', s?.devices)}
        {tile('security', 'mit Sicherheitsupdates', s?.withSecurity, 'sev-tile-high')}
        {tile('missing', 'mit ausstehenden Updates', s?.withMissing, 'sev-tile-medium')}
        {tile('reboot', 'Neustart ausstehend', s?.rebootPending, 'sev-tile-low')}
        {tile('never', 'nie gescannt', s?.neverScanned)}
        {tile('failed', 'Scan fehlgeschlagen', s?.scanFailed, 'tile-kev')}
      </div>
      <div className="tabs" role="tablist">
        <button role="tab" className={tab === 'devices' ? 'tab active' : 'tab'} onClick={() => setTab('devices')}>
          Geräte
        </button>
        <button role="tab" className={tab === 'updates' ? 'tab active' : 'tab'} onClick={() => setTab('updates')}>
          Updates
        </button>
      </div>
      {tab === 'devices' && <DeviceList filter={filter} />}
      {tab === 'updates' && <UpdateList selected={selected} onSelect={setSelected} onInstall={can('patches:execute') ? () => setPanel('install') : undefined} />}
    </>
  );
}

function DeviceList({ filter }: { filter: Filter }) {
  const [search, setSearch] = useState('');
  const list = useLoad(() => unwrap(api.GET('/patches/devices', { params: { query: { filter, search: search || undefined, limit: 500 } } })), [filter, search]);
  return (
    <>
      <input className="table-filter" placeholder="Gerät suchen …" value={search} onChange={(e) => setSearch(e.target.value)} />
      {list.error && <div className="error">{list.error}</div>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Gerät</th>
              <th>Kritisch</th>
              <th>Sicherheit</th>
              <th>Gesamt</th>
              <th>Neustart</th>
              <th>Letzter Scan</th>
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((d) => (
              <tr key={d.deviceId}>
                <td>
                  <Link to={`/devices/${d.deviceId}`} state={{ tab: 'Updates' }}>
                    {d.hostname}
                  </Link>
                  <div className="muted small">
                    {d.os} {d.osVersion}
                  </div>
                </td>
                <td>{d.critical ? <span className="badge danger">{d.critical}</span> : '0'}</td>
                <td>{d.security ? <span className="badge warn">{d.security}</span> : '0'}</td>
                <td>{d.missing}</td>
                <td>{d.rebootPending ? <span className="badge warn">ja</span> : '–'}</td>
                <td>
                  {d.lastScanAt ? fmtDate(d.lastScanAt) : <span className="muted">nie</span>}
                  {d.lastScanStatus === 'failed' && <div className="error-text small" title={d.lastError ?? ''}>fehlgeschlagen{d.lastError?.startsWith('integrity:') ? ' (Hash-Prüfung)' : ''}</div>}
                </td>
              </tr>
            ))}
            {list.data?.items.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  Keine Geräte.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {list.data && list.data.total > list.data.items.length && <p className="muted">{list.data.items.length} von {list.data.total} angezeigt.</p>}
    </>
  );
}

function UpdateList({ selected, onSelect, onInstall }: { selected: string[]; onSelect: (ids: string[]) => void; onInstall?: () => void }) {
  const [search, setSearch] = useState('');
  const [security, setSecurity] = useState(false);
  const list = useLoad(() => unwrap(api.GET('/patches/updates', { params: { query: { search: search || undefined, security: security ? 'true' : undefined, limit: 500 } } })), [search, security]);
  const toggle = (id: string) => onSelect(selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id]);
  return (
    <>
      <div className="form-inline">
        <input className="table-filter" placeholder="Titel, KB oder Paket …" value={search} onChange={(e) => setSearch(e.target.value)} />
        <label className="check">
          <input type="checkbox" checked={security} onChange={(e) => setSecurity(e.target.checked)} /> nur Sicherheitsupdates
        </label>
        {onInstall && selected.length > 0 && <button onClick={onInstall}>{selected.length} ausgewählte installieren …</button>}
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              {onInstall && <th />}
              <th>Update</th>
              <th>Quelle</th>
              <th>Klassifikation</th>
              <th>Geräte</th>
              <th>Erkannt seit</th>
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((u) => {
              const key = u.kb && u.source === 'windows_update' ? u.kb.split(',')[0]! : u.updateId;
              return (
                <tr key={`${u.source}:${u.updateId}`}>
                  {onInstall && (
                    <td>
                      <input type="checkbox" checked={selected.includes(key)} onChange={() => toggle(key)} />
                    </td>
                  )}
                  <td>
                    {u.title}
                    {u.kb && <div className="muted small">{u.kb}</div>}
                  </td>
                  <td>{SOURCE_LABEL[u.source] ?? u.source}</td>
                  <td>
                    {u.security && <span className="badge warn">Sicherheit</span>} {u.severity && <span className={u.severity.toLowerCase() === 'critical' ? 'badge danger' : 'badge'}>{u.severity}</span>}{' '}
                    <span className="muted small">{u.classification}</span>
                    {u.rebootRequired && <div className="muted small">Neustart nötig</div>}
                  </td>
                  <td>{u.devices}</td>
                  <td>{fmtDate(u.firstDetectedAt)}</td>
                </tr>
              );
            })}
            {list.data?.items.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  Keine ausstehenden Updates bekannt.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

function ScanPanel({ onDone }: { onDone: () => void }) {
  const [targets, setTargets] = useState<Targets>({ ...emptyTargets(), allDevices: true });
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function scan() {
    setError(null);
    try {
      const r = await unwrap(api.POST('/patches/scan', { body: { targets } }));
      setMsg(`Scan auf ${r.devices} Gerät(en) angefordert – Ergebnisse erscheinen, sobald die Geräte geantwortet haben.`);
      setTimeout(onDone, 2500);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <div className="card highlight">
      <h2>Nach ausstehenden Updates suchen</h2>
      <TargetPicker value={targets} onChange={setTargets} />
      {msg && <p>{msg}</p>}
      {error && <div className="error">{error}</div>}
      <button disabled={!hasTargets(targets)} onClick={() => void scan()}>
        Scan starten
      </button>
    </div>
  );
}

function InstallPanel({ include, onCancel }: { include: string[]; onCancel: () => void }) {
  const navigate = useNavigate();
  const [classification, setClassification] = useState<'critical' | 'security' | 'all'>('security');
  const [useSelection, setUseSelection] = useState(include.length > 0);
  const [reboot, setReboot] = useState<'never' | 'if_required'>('never');
  const [rings, setRings] = useState<Ring[]>(DEFAULT_RINGS.map((r) => ({ ...r, targets: { ...r.targets } })));
  const [error, setError] = useState<string | null>(null);
  async function submit() {
    setError(null);
    try {
      const r = await startDeployment({ kind: 'os_updates', patchFilter: { classification, include: useSelection ? include : [], reboot }, rings });
      navigate(`/deployments/${r.id}`);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <div className="card highlight">
      <h2>Updates installieren</h2>
      <div className="form-inline">
        {include.length > 0 && (
          <label className="check">
            <input type="checkbox" checked={useSelection} onChange={(e) => setUseSelection(e.target.checked)} /> nur die {include.length} ausgewählten Updates
          </label>
        )}
        {!useSelection && (
          <select value={classification} onChange={(e) => setClassification(e.target.value as typeof classification)}>
            <option value="critical">kritische Updates</option>
            <option value="security">Sicherheitsupdates</option>
            <option value="all">alle Updates (ohne Treiber und Funktionsupgrades)</option>
          </select>
        )}
        <select value={reboot} onChange={(e) => setReboot(e.target.value as typeof reboot)}>
          <option value="never">nie automatisch neu starten</option>
          <option value="if_required">bei Bedarf neu starten (5 min Vorwarnung)</option>
        </select>
      </div>
      <p className="muted small">Windows über Windows Update/WSUS, Linux über apt bzw. dnf, macOS über softwareupdate. Nach der Installation wird automatisch neu gescannt.</p>
      <RingsEditor value={rings} onChange={setRings} />
      {error && <div className="error">{error}</div>}
      <p>
        <button disabled={!rings.every((r) => hasTargets(r.targets) && r.name.trim())} onClick={() => void submit()}>
          Verteilung starten
        </button>{' '}
        <button className="link" onClick={onCancel}>
          Abbrechen
        </button>
      </p>
    </div>
  );
}

/** Tab in the device view: pending updates of one device. */
export function DevicePatchesTab({ deviceId }: { deviceId: string }) {
  const { canScoped } = useAuth();
  const data = useLoad(() => unwrap(api.GET('/devices/{id}/patches', { params: { path: { id: deviceId } } })), [deviceId]);
  const [msg, setMsg] = useState<string | null>(null);
  if (data.error) return <div className="error">{data.error}</div>;
  if (!data.data) return <div className="muted">Lade …</div>;
  const st = data.data.state;
  async function scan() {
    try {
      await unwrap(api.POST('/patches/scan', { body: { targets: { deviceIds: [deviceId] } } }));
      setMsg('Scan angefordert.');
    } catch (e) {
      setMsg((e as Error).message);
    }
  }
  return (
    <>
      <div className="toolbar">
        <p>
          Letzter Scan: {st.lastScanAt ? fmtDate(st.lastScanAt) : 'nie'}
          {st.source && ` (${SOURCE_LABEL[st.source] ?? st.source})`}
          {st.lastScanStatus === 'failed' && <span className="error-text"> – fehlgeschlagen: {st.lastError}</span>}
          {st.rebootPending && <span className="badge warn"> Neustart ausstehend</span>}
        </p>
        {canScoped('patches:execute') && (
          <button className="link" onClick={() => void scan()}>
            Jetzt scannen
          </button>
        )}
      </div>
      {msg && <p className="muted">{msg}</p>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Update</th>
              <th>Klassifikation</th>
              <th>Erkannt</th>
            </tr>
          </thead>
          <tbody>
            {data.data.items.map((u) => (
              <tr key={u.updateId}>
                <td>
                  {u.title}
                  {u.kb && <div className="muted small">{u.kb}</div>}
                </td>
                <td>
                  {u.security && <span className="badge warn">Sicherheit</span>} {u.severity} <span className="muted small">{u.classification}</span>
                </td>
                <td>{fmtDate(u.detectedAt)}</td>
              </tr>
            ))}
            {data.data.items.length === 0 && (
              <tr>
                <td colSpan={3} className="muted">
                  {st.lastScanAt ? 'Keine ausstehenden Updates.' : 'Noch nicht gescannt.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
