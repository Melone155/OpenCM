import { useState, type ReactNode } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import { api, unwrap } from '../api/client';
import { CustomFieldsTab } from '../components/CustomFieldsTab';
import { DeviceVulnsTab } from '../components/DeviceVulnsTab';
import { useAuth } from '../auth';
import { fmtBytes, fmtRelative, OS_LABEL, val } from '../format';
import { fmtDate, useLoad } from '../hooks';
import { DeviceAssetsTab } from './AssetsPage';
import { DevicePatchesTab } from './PatchesPage';
import { DeviceSecurityTab } from './SecurityPage';
import { DeleteButton } from './UsersPage';

const TABS = ['Übersicht', 'Sicherheit', 'Schwachstellen', 'Updates', 'Software', 'Dienste', 'Benutzer & Gruppen', 'Netzwerk & Datenträger', 'Patches', 'Zubehör', 'Eigene Felder', 'Historie'] as const;
type Tab = (typeof TABS)[number];

function Facts({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="facts">
      {rows.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{v ?? '–'}</dd>
        </div>
      ))}
    </dl>
  );
}

export function DevicePage() {
  const { id = '' } = useParams();
  const { can, canScoped } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [tab, setTab] = useState<Tab>(((location.state as { tab?: Tab } | null)?.tab as Tab) ?? 'Übersicht');
  const [msg, setMsg] = useState<string | null>(null);
  const device = useLoad(() => unwrap(api.GET('/devices/{id}', { params: { path: { id } } })), [id]);
  const inv = useLoad(
    () =>
      can('inventory:read')
        ? api.GET('/devices/{id}/inventory', { params: { path: { id } } }).then((r) => r.data ?? null)
        : Promise.resolve(null),
    [id],
  );

  const d = device.data;
  if (device.error) return <div className="error">{device.error}</div>;
  if (!d) return <div className="muted">Lade …</div>;
  const i = inv.data;

  async function act(p: Promise<unknown>, done: string) {
    setMsg(null);
    try {
      await p;
      setMsg(done);
      await device.reload();
    } catch (e) {
      setMsg((e as Error).message);
    }
  }

  return (
    <>
      <div className="toolbar">
        <h1>
          <Link to="/devices" className="muted">
            Geräte
          </Link>{' '}
          / {d.hostname}
        </h1>
        {d.status === 'revoked' ? (
          <span className="badge danger">widerrufen</span>
        ) : d.online ? (
          <span className="badge ok">online</span>
        ) : (
          <span className="badge">offline</span>
        )}
        {can('inventory:update') && d.status === 'active' && (
          <button
            onClick={() =>
              void act(unwrap(api.POST('/devices/{id}/inventory-request', { params: { path: { id } } })), 'Inventar angefordert – kommt mit dem nächsten Heartbeat.')
            }
            disabled={d.inventoryRequested}
          >
            {d.inventoryRequested ? 'Inventar angefordert' : 'Inventar anfordern'}
          </button>
        )}
        {can('devices:update') && d.status === 'active' && (
          <button className="link danger" onClick={() => void act(unwrap(api.POST('/devices/{id}/revoke', { params: { path: { id } } })), 'Zertifikat widerrufen.')}>
            Widerrufen
          </button>
        )}
        {can('devices:delete') && (
          <DeleteButton onConfirm={() => unwrap(api.DELETE('/devices/{id}', { params: { path: { id } } })).then(() => navigate('/devices'))} />
        )}
      </div>
      {msg && <div className="card">{msg}</div>}

      <div className="tabs" role="tablist">
        {TABS.filter((t) => (t !== 'Updates' || canScoped('patches:read')) && (t !== 'Sicherheit' || canScoped('inventory:read')) && (t !== 'Zubehör' || can('assets:read'))).map((t) => (
          <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? 'tab active' : 'tab'} onClick={() => setTab(t)}>
            {t}
          </button>
        ))}
      </div>

      {tab === 'Übersicht' && (
        <div className="grid2">
          <div className="card">
            <h2>Gerät</h2>
            <Facts
              rows={[
                ['Hostname', d.hostname],
                ['Betriebssystem', `${OS_LABEL[d.os]} ${d.osVersion}`],
                ['Architektur', d.arch],
                ['Angemeldet', d.loggedOnUser],
                ['Letzter Kontakt', `${fmtRelative(d.lastSeenAt)} (${fmtDate(d.lastSeenAt)})`],
                ['Letzte IP', d.lastIp],
                ['Letztes Inventar', fmtDate(d.lastInventoryAt)],
                ['Registriert', fmtDate(d.enrolledAt)],
                ['Agent-Version', d.agentVersion],
                ['Zertifikat gültig bis', fmtDate(d.certExpiresAt)],
                ['Gruppen', d.groups.map((g) => g.name).join(', ') || '–'],
              ]}
            />
          </div>
          <div className="card">
            <h2>Hardware</h2>
            {i ? (
              <Facts
                rows={[
                  ['Hersteller', val(i.hardware.manufacturer)],
                  ['Modell', val(i.hardware.model)],
                  ['Seriennummer', val(i.hardware.serialNumber)],
                  ['Bauform', val(i.hardware.chassis)],
                  ['CPU', val(i.hardware.cpu?.model)],
                  ['Kerne / Threads', `${val(i.hardware.cpu?.cores)} / ${val(i.hardware.cpu?.logicalProcessors)}`],
                  ['Arbeitsspeicher', fmtBytes(i.hardware.memoryBytes)],
                  ['BIOS', [i.hardware.biosVendor, i.hardware.biosVersion].filter(Boolean).join(' ') || '–'],
                  ['BIOS-Datum', val(i.hardware.biosDate)],
                  ['OS-Build', val(i.os.build)],
                  ['Kernel', val(i.os.kernel)],
                  ['Letzter Start', fmtDate(i.os.lastBoot)],
                  ['OS installiert', fmtDate(i.os.installDate)],
                ]}
              />
            ) : (
              <p className="muted">Noch kein Inventar empfangen.</p>
            )}
          </div>
        </div>
      )}

      {tab === 'Software' && <SoftwareTab id={id} />}

      {tab === 'Dienste' && i && (
        <SimpleTable
          headers={['Name', 'Anzeigename', 'Status', 'Starttyp']}
          rows={i.services.map((s) => [s.name, val(s.displayName), val(s.state), val(s.startMode)])}
          filter
        />
      )}

      {tab === 'Benutzer & Gruppen' && i && (
        <>
          <h2>Angemeldet: {i.loggedOnUsers.join(', ') || '–'}</h2>
          <SimpleTable
            headers={['Lokaler Benutzer', 'Voller Name', 'Status', 'ID']}
            rows={i.localUsers.map((u) => [u.name, val(u.fullName), u.disabled ? 'deaktiviert' : 'aktiv', val(u.uid)])}
          />
          <SimpleTable headers={['Lokale Gruppe', 'Mitglieder']} rows={i.localGroups.map((g) => [g.name, g.members.join(', ') || '–'])} filter />
          <h2>Autostart</h2>
          <SimpleTable headers={['Name', 'Befehl', 'Ort']} rows={i.autostart.map((a) => [a.name, val(a.command), val(a.location)])} />
        </>
      )}

      {tab === 'Netzwerk & Datenträger' && i && (
        <>
          <SimpleTable
            headers={['Schnittstelle', 'MAC', 'Status', 'IPv4', 'IPv6']}
            rows={i.network.map((n) => [n.name, val(n.mac), n.up ? 'aktiv' : 'inaktiv', n.ipv4.join(', ') || '–', n.ipv6.join(', ') || '–'])}
          />
          <SimpleTable
            headers={['Datenträger', 'Einhängepunkt', 'Dateisystem', 'Größe', 'Frei']}
            rows={i.disks.map((x) => [
              x.name,
              val(x.mount),
              val(x.fsType),
              fmtBytes(x.sizeBytes),
              x.sizeBytes && x.freeBytes ? `${fmtBytes(x.freeBytes)} (${Math.round((x.freeBytes / x.sizeBytes) * 100)} %)` : '–',
            ])}
          />
        </>
      )}

      {tab === 'Patches' && i && (
        <SimpleTable
          headers={['Patch', 'Beschreibung', 'Installiert']}
          rows={[...i.patches].sort((a, b) => (b.installedOn ?? '').localeCompare(a.installedOn ?? '')).map((p) => [p.id, val(p.description), fmtDate(p.installedOn)])}
          filter
        />
      )}

      {tab === 'Eigene Felder' && <CustomFieldsTab deviceId={id} />}

      {tab === 'Schwachstellen' && <DeviceVulnsTab deviceId={id} />}

      {tab === 'Updates' && <DevicePatchesTab deviceId={id} />}

      {tab === 'Historie' && <HistoryTab id={id} />}

      {tab === 'Sicherheit' && <DeviceSecurityTab deviceId={id} />}

      {tab === 'Zubehör' && <DeviceAssetsTab deviceId={id} />}

      {!['Übersicht', 'Software', 'Historie', 'Eigene Felder', 'Schwachstellen', 'Updates', 'Sicherheit', 'Zubehör'].includes(tab) && !i && <p className="muted">Noch kein Inventar empfangen.</p>}
    </>
  );
}

function SimpleTable({ headers, rows, filter }: { headers: string[]; rows: string[][]; filter?: boolean }) {
  const [q, setQ] = useState('');
  const shown = q ? rows.filter((r) => r.some((c) => c.toLowerCase().includes(q.toLowerCase()))) : rows;
  return (
    <>
      {filter && <input className="table-filter" placeholder="Filtern …" value={q} onChange={(e) => setQ(e.target.value)} />}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              {headers.map((h) => (
                <th key={h}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((r, idx) => (
              <tr key={idx}>
                {r.map((c, j) => (
                  <td key={j} className={j > 0 ? 'perms' : undefined}>
                    {c}
                  </td>
                ))}
              </tr>
            ))}
            {shown.length === 0 && (
              <tr>
                <td colSpan={headers.length} className="muted">
                  Keine Einträge
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="muted">{shown.length} Einträge</div>
    </>
  );
}

function SoftwareTab({ id }: { id: string }) {
  const [search, setSearch] = useState('');
  const sw = useLoad(() => unwrap(api.GET('/devices/{id}/software', { params: { path: { id }, query: { search: search || undefined } } })), [id, search]);
  return (
    <>
      <input className="table-filter" placeholder="Name oder Hersteller …" value={search} onChange={(e) => setSearch(e.target.value)} />
      {sw.error && <div className="error">{sw.error}</div>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Version</th>
              <th>Hersteller</th>
              <th>Installiert</th>
              <th>Quelle</th>
              <th>Arch.</th>
            </tr>
          </thead>
          <tbody>
            {sw.data?.items.map((s, idx) => (
              <tr key={idx}>
                <td>{s.name}</td>
                <td>{s.version || '–'}</td>
                <td>{s.publisher || '–'}</td>
                <td>{s.installDate ?? '–'}</td>
                <td className="muted">{s.source}</td>
                <td className="muted">{s.arch}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {sw.data && <div className="muted">{sw.data.items.length} Pakete</div>}
    </>
  );
}

const CHANGE_LABEL: Record<string, string> = { added: 'hinzugefügt', removed: 'entfernt', changed: 'geändert' };

function HistoryTab({ id }: { id: string }) {
  const [category, setCategory] = useState('');
  const hist = useLoad(
    () =>
      unwrap(
        api.GET('/devices/{id}/history', {
          params: { path: { id }, query: { category: (category || undefined) as never, limit: 500 } },
        }),
      ),
    [id, category],
  );
  return (
    <>
      <select value={category} onChange={(e) => setCategory(e.target.value)}>
        <option value="">Alle Kategorien</option>
        {['software', 'security', 'hardware', 'os', 'patch', 'service', 'autostart', 'user', 'group', 'disk', 'device'].map((c) => (
          <option key={c} value={c}>
            {c}
          </option>
        ))}
      </select>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Zeit</th>
              <th>Kategorie</th>
              <th>Änderung</th>
              <th>Objekt</th>
              <th>Alt</th>
              <th>Neu</th>
            </tr>
          </thead>
          <tbody>
            {hist.data?.items.map((h) => (
              <tr key={h.id}>
                <td>{fmtDate(h.at)}</td>
                <td>{h.category}</td>
                <td>
                  <span className={h.change === 'removed' ? 'badge danger' : h.change === 'added' ? 'badge ok' : 'badge'}>{CHANGE_LABEL[h.change]}</span>
                </td>
                <td>{h.itemKey}</td>
                <td className="perms">{val(h.oldValue)}</td>
                <td className="perms">{val(h.newValue)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {hist.data && <div className="muted">{hist.data.total} Änderungen</div>}
    </>
  );
}
