import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, jsonOnly, unwrap, type Schemas } from '../api/client';
import { useAuth } from '../auth';
import { useLoad } from '../hooks';
import { DeleteButton } from './UsersPage';

type Asset = Schemas['Asset'];
type AssetType = Schemas['AssetType'];
type AssetStatus = Schemas['AssetStatus'];
type ImportResult = Schemas['AssetImportResult'];

export const TYPE_LABEL: Record<AssetType, string> = {
  computer: 'Computer',
  notebook: 'Notebook',
  server: 'Server',
  monitor: 'Monitor',
  printer: 'Drucker',
  phone: 'Telefon',
  tablet: 'Tablet',
  network: 'Netzwerkgerät',
  peripheral: 'Peripherie',
  other: 'Sonstiges',
};
export const STATUS_LABEL: Record<AssetStatus, string> = { in_stock: 'Lager', in_use: 'In Benutzung', repair: 'Reparatur', retired: 'Ausgemustert' };

const fmtDay = (d: string | null | undefined) => (d ? new Date(`${d}T00:00:00Z`).toLocaleDateString('de-DE', { timeZone: 'UTC' }) : '–');
const daysUntil = (d: string) => Math.round((Date.parse(`${d}T00:00:00Z`) - Date.parse(`${new Date().toISOString().slice(0, 10)}T00:00:00Z`)) / 86_400_000);

/** Warranty date with a text badge (expired / soon). */
function Warranty({ asset }: { asset: Pick<Asset, 'warrantyUntil' | 'status'> }) {
  if (!asset.warrantyUntil) return <>–</>;
  const left = daysUntil(asset.warrantyUntil);
  return (
    <>
      {fmtDay(asset.warrantyUntil)}
      {asset.status !== 'retired' && left < 0 && <span className="badge danger"> abgelaufen</span>}
      {asset.status !== 'retired' && left >= 0 && left <= 30 && <span className="badge warn"> in {left} Tagen</span>}
    </>
  );
}

type Form = {
  id?: string;
  name: string;
  type: AssetType;
  status: AssetStatus;
  manufacturer: string;
  model: string;
  serialNumber: string;
  inventoryNumber: string;
  location: string;
  assignedTo: string;
  ipAddress: string;
  macAddress: string;
  purchaseDate: string;
  warrantyUntil: string;
  cost: string;
  deviceId: string;
  deviceHostname: string;
  notes: string;
};
const EMPTY: Form = {
  name: '',
  type: 'monitor',
  status: 'in_use',
  manufacturer: '',
  model: '',
  serialNumber: '',
  inventoryNumber: '',
  location: '',
  assignedTo: '',
  ipAddress: '',
  macAddress: '',
  purchaseDate: '',
  warrantyUntil: '',
  cost: '',
  deviceId: '',
  deviceHostname: '',
  notes: '',
};
const toForm = (a: Asset): Form => ({
  id: a.id,
  name: a.name,
  type: a.type,
  status: a.status,
  manufacturer: a.manufacturer,
  model: a.model,
  serialNumber: a.serialNumber ?? '',
  inventoryNumber: a.inventoryNumber ?? '',
  location: a.location,
  assignedTo: a.assignedTo,
  ipAddress: a.ipAddress ?? '',
  macAddress: a.macAddress ?? '',
  purchaseDate: a.purchaseDate ?? '',
  warrantyUntil: a.warrantyUntil ?? '',
  cost: a.cost === null || a.cost === undefined ? '' : String(a.cost),
  deviceId: a.deviceId ?? '',
  deviceHostname: a.deviceHostname ?? '',
  notes: a.notes,
});

/** Picks one managed device by host name search. */
function DeviceSelect({ value, label, onChange }: { value: string; label: string; onChange: (id: string, hostname: string) => void }) {
  const [search, setSearch] = useState('');
  const found = useLoad(() => (search.length < 2 ? Promise.resolve({ items: [], total: 0 }) : unwrap(api.GET('/devices', { params: { query: { search, status: 'active', limit: 20 } } }))), [search]);
  return (
    <div>
      {value ? (
        <div className="form-inline">
          <span>{label || value}</span>
          <button type="button" className="link danger" onClick={() => onChange('', '')}>
            Verknüpfung lösen
          </button>
        </div>
      ) : (
        <>
          <input placeholder="Hostname suchen (mind. 2 Zeichen) …" value={search} onChange={(e) => setSearch(e.target.value)} />
          {(found.data?.items ?? []).length > 0 && (
            <ul className="plain picker-list">
              {found.data!.items.map((d) => (
                <li key={d.id}>
                  <button
                    type="button"
                    className="link"
                    onClick={() => {
                      onChange(d.id, d.hostname);
                      setSearch('');
                    }}
                  >
                    {d.hostname}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}

function AssetEditor({ initial, onDone }: { initial: Form; onDone: (saved: boolean) => void }) {
  const [form, setForm] = useState<Form>(initial);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (patch: Partial<Form>) => setForm({ ...form, ...patch });
  const text = (key: keyof Form, label: string, placeholder = '', type = 'text') => (
    <label>
      {label}
      <input type={type} value={form[key] as string} placeholder={placeholder} onChange={(e) => set({ [key]: e.target.value } as Partial<Form>)} />
    </label>
  );

  async function save() {
    setBusy(true);
    setError(null);
    const opt = (v: string) => (v.trim() ? v.trim() : null);
    const body = {
      name: form.name.trim(),
      type: form.type,
      status: form.status,
      manufacturer: form.manufacturer.trim(),
      model: form.model.trim(),
      serialNumber: opt(form.serialNumber),
      inventoryNumber: opt(form.inventoryNumber),
      location: form.location.trim(),
      assignedTo: form.assignedTo.trim(),
      ipAddress: opt(form.ipAddress),
      macAddress: opt(form.macAddress),
      purchaseDate: opt(form.purchaseDate),
      warrantyUntil: opt(form.warrantyUntil),
      cost: form.cost.trim() ? Number(form.cost.replace(',', '.')) : null,
      deviceId: form.deviceId || null,
      notes: form.notes,
    };
    try {
      if (form.id) await unwrap(api.PATCH('/assets/{id}', { params: { path: { id: form.id } }, body }));
      else await unwrap(api.POST('/assets', { body }));
      onDone(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card highlight">
      <h2>{form.id ? `Asset bearbeiten: ${initial.name}` : 'Asset erfassen'}</h2>
      {error && <div className="error">{error}</div>}
      <div className="form-grid">
        {text('name', 'Bezeichnung *', 'Monitor Empfang')}
        <label>
          Typ
          <select value={form.type} onChange={(e) => set({ type: e.target.value as AssetType })}>
            {Object.entries(TYPE_LABEL).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label>
          Status
          <select value={form.status} onChange={(e) => set({ status: e.target.value as AssetStatus })}>
            {Object.entries(STATUS_LABEL).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
        </label>
        {text('inventoryNumber', 'Inventarnummer', 'eindeutig, z. B. INV-0001')}
        {text('manufacturer', 'Hersteller')}
        {text('model', 'Modell')}
        {text('serialNumber', 'Seriennummer')}
        {text('location', 'Standort', 'Gebäude / Raum')}
        {text('assignedTo', 'Zugeordnet an', 'Person oder Abteilung')}
        {text('ipAddress', 'IP-Adresse', '10.0.0.50')}
        {text('macAddress', 'MAC-Adresse', '00:11:22:33:44:55')}
        {text('purchaseDate', 'Kaufdatum', '', 'date')}
        {text('warrantyUntil', 'Garantie bis', '', 'date')}
        {text('cost', 'Kosten', '0,00')}
        <label>
          Gehört zu Gerät (optional)
          <DeviceSelect value={form.deviceId} label={form.deviceHostname} onChange={(id, hostname) => set({ deviceId: id, deviceHostname: hostname })} />
        </label>
        <label style={{ gridColumn: '1 / -1' }}>
          Notizen
          <textarea rows={3} value={form.notes} onChange={(e) => set({ notes: e.target.value })} />
        </label>
      </div>
      <p>
        <button disabled={busy || !form.name.trim()} onClick={() => void save()}>
          Speichern
        </button>{' '}
        <button className="link" onClick={() => onDone(false)}>
          Abbrechen
        </button>
      </p>
    </div>
  );
}

const TEMPLATE = 'Bezeichnung;Typ;Status;Hersteller;Modell;Seriennummer;Inventarnummer;Standort;Benutzer;IP;MAC;Kaufdatum;Garantie bis;Kosten;Gerät;Notizen\r\nMonitor Empfang;Monitor;In Benutzung;Contoso;View 27;MON-0001;INV-0001;Empfang;Frau Beispiel;;;01.03.2025;28.02.2028;249,90;PC-0815;\r\n';

function ImportCard({ onDone }: { onDone: () => void }) {
  const [csv, setCsv] = useState<string | null>(null);
  const [fileName, setFileName] = useState('');
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(dryRun: boolean, text = csv) {
    if (!text) return;
    setBusy(true);
    setError(null);
    try {
      const r = await unwrap(api.POST('/assets/import', { body: { csv: text, dryRun } }));
      setResult(r);
      if (!dryRun) onDone();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function pick(file: File | undefined) {
    if (!file) return;
    setFileName(file.name);
    setResult(null);
    // Excel often saves CSV as Windows-1252; fall back when the UTF-8 decoding contains replacement characters
    const buf = await file.arrayBuffer();
    let text = new TextDecoder('utf-8').decode(buf);
    if (text.includes('�')) text = new TextDecoder('windows-1252').decode(buf);
    setCsv(text);
    await run(true, text);
  }

  return (
    <div className="card highlight">
      <h2>CSV importieren</h2>
      <p className="muted small">
        Spalten mit deutschen oder englischen Namen, getrennt durch Semikolon (Excel) oder Komma. Pflicht ist nur „Bezeichnung“. Vorhandene Assets werden über die Inventarnummer, sonst über die Seriennummer erkannt und aktualisiert. Datum als
        TT.MM.JJJJ oder JJJJ-MM-TT.{' '}
        <a href={`data:text/csv;charset=utf-8,${encodeURIComponent(`﻿${TEMPLATE}`)}`} download="opencm-assets-vorlage.csv">
          Vorlage herunterladen
        </a>
      </p>
      <input type="file" accept=".csv,text/csv" onChange={(e) => void pick(e.target.files?.[0])} />
      {error && <div className="error">{error}</div>}
      {result && (
        <div>
          <p>
            <strong>{result.dryRun ? `Probelauf für ${fileName}` : 'Import abgeschlossen'}:</strong> {result.rows} Zeilen – {result.created} neu, {result.updated} aktualisiert, {result.skipped} übersprungen.
          </p>
          {result.errors.length > 0 && (
            <ul className="plain small scroll-list">
              {result.errors.map((e) => (
                <li key={`e${e.line}`} className="error-text">
                  Zeile {e.line}: {e.message}
                </li>
              ))}
            </ul>
          )}
          {result.warnings.length > 0 && (
            <ul className="plain small scroll-list">
              {result.warnings.map((w) => (
                <li key={`w${w.line}`}>
                  <span className="badge warn">Hinweis</span> Zeile {w.line}: {w.message}
                </li>
              ))}
            </ul>
          )}
          {result.unknownColumns.length > 0 && <p className="muted small">Ignorierte Spalten: {result.unknownColumns.join(', ')}</p>}
          {result.dryRun && result.created + result.updated > 0 && (
            <button disabled={busy} onClick={() => void run(false)}>
              {result.created + result.updated} Zeilen jetzt importieren
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/** Assets without an agent: monitors, printers, phones, network gear, spare devices. */
export function AssetsPage() {
  const { can } = useAuth();
  const [search, setSearch] = useState('');
  const [type, setType] = useState('');
  const [status, setStatus] = useState('');
  const [warranty, setWarranty] = useState('');
  const [hideRetired, setHideRetired] = useState(true);
  const [offset, setOffset] = useState(0);
  const [editing, setEditing] = useState<Form | null>(null);
  const [importing, setImporting] = useState(false);
  const limit = 100;
  const query = {
    search: search || undefined,
    type: (type || undefined) as AssetType | undefined,
    status: (status || undefined) as AssetStatus | undefined,
    warrantyDays: warranty ? Number(warranty) : undefined,
    includeRetired: (hideRetired ? 'false' : 'true') as 'true' | 'false',
    sort: (warranty ? 'warrantyUntil' : 'name') as 'name' | 'warrantyUntil',
  };
  const list = useLoad(() => jsonOnly(unwrap(api.GET('/assets', { params: { query: { ...query, limit, offset } } }))), [JSON.stringify(query), offset]);
  const csvQuery = Object.fromEntries(Object.entries({ ...query, format: 'csv' }).filter(([, v]) => v !== undefined).map(([k, v]) => [k, String(v)]));

  return (
    <>
      <div className="toolbar">
        <h1>Assets</h1>
        {can('assets:create') && (
          <button onClick={() => { setEditing({ ...EMPTY }); setImporting(false); }}>
            Asset erfassen
          </button>
        )}
        {can('assets:create') && can('assets:update') && (
          <button className="link" onClick={() => { setImporting(!importing); setEditing(null); }}>
            CSV importieren
          </button>
        )}
        <a className="button" href={`/api/v1/assets?${new URLSearchParams(csvQuery)}`}>
          CSV exportieren
        </a>
      </div>
      <p className="muted">Geräte ohne Agent – Monitore, Drucker, Telefone, Netzwerkgeräte, Ersatzgeräte im Lager. Assets lassen sich einem verwalteten Gerät zuordnen (z. B. Monitore zum PC).</p>

      {editing && (
        <AssetEditor
          key={editing.id ?? 'new'}
          initial={editing}
          onDone={(saved) => {
            setEditing(null);
            if (saved) void list.reload();
          }}
        />
      )}
      {importing && <ImportCard onDone={() => void list.reload()} />}

      <div className="form-inline">
        <input placeholder="Name, Seriennr., Inventarnr., Person, Standort, IP …" value={search} onChange={(e) => { setSearch(e.target.value); setOffset(0); }} style={{ minWidth: 'min(340px, 100%)' }} />
        <select value={type} onChange={(e) => { setType(e.target.value); setOffset(0); }} aria-label="Typ">
          <option value="">Alle Typen</option>
          {Object.entries(TYPE_LABEL).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
        <select value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }} aria-label="Status">
          <option value="">Alle Status</option>
          {Object.entries(STATUS_LABEL).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
        <select value={warranty} onChange={(e) => { setWarranty(e.target.value); setOffset(0); }} aria-label="Garantie">
          <option value="">Garantie: alle</option>
          <option value="0">abgelaufen</option>
          <option value="30">läuft in 30 Tagen ab</option>
          <option value="90">läuft in 90 Tagen ab</option>
        </select>
        <label className="check">
          <input type="checkbox" checked={hideRetired} onChange={(e) => { setHideRetired(e.target.checked); setOffset(0); }} />
          Ausgemusterte ausblenden
        </label>
      </div>

      {list.error && <div className="error">{list.error}</div>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Bezeichnung</th>
              <th>Typ</th>
              <th>Status</th>
              <th>Inventar-Nr.</th>
              <th>Seriennr.</th>
              <th>Standort / Person</th>
              <th>Garantie</th>
              <th>Gerät</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((a) => (
              <tr key={a.id} className={a.status === 'retired' ? 'muted' : undefined}>
                <td>
                  {a.name}
                  {(a.manufacturer || a.model) && <div className="muted small">{[a.manufacturer, a.model].filter(Boolean).join(' ')}</div>}
                  {a.ipAddress && <div className="muted small">{a.ipAddress}</div>}
                </td>
                <td>{TYPE_LABEL[a.type]}</td>
                <td>{STATUS_LABEL[a.status]}</td>
                <td>{a.inventoryNumber ?? '–'}</td>
                <td>{a.serialNumber ?? '–'}</td>
                <td>
                  {a.location || '–'}
                  {a.assignedTo && <div className="muted small">{a.assignedTo}</div>}
                </td>
                <td>
                  <Warranty asset={a} />
                </td>
                <td>{a.deviceId ? <Link to={`/devices/${a.deviceId}`}>{a.deviceHostname}</Link> : '–'}</td>
                <td className="actions">
                  {can('assets:update') && (
                    <button className="link" onClick={() => { setEditing(toForm(a)); setImporting(false); }}>
                      Bearbeiten
                    </button>
                  )}
                  {can('assets:delete') && <DeleteButton onConfirm={() => unwrap(api.DELETE('/assets/{id}', { params: { path: { id: a.id } } })).then(() => list.reload())} />}
                </td>
              </tr>
            ))}
            {list.data?.items.length === 0 && (
              <tr>
                <td colSpan={9} className="muted">
                  Keine Assets für diese Auswahl.
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

/** "Zubehör" tab on the device page: assets linked to this device. */
export function DeviceAssetsTab({ deviceId }: { deviceId: string }) {
  const list = useLoad(() => unwrap(api.GET('/devices/{id}/assets', { params: { path: { id: deviceId } } })), [deviceId]);
  if (list.error) return <div className="error">{list.error}</div>;
  return (
    <>
      <p className="muted">
        Assets ohne Agent, die diesem Gerät zugeordnet sind (z. B. Monitore, Dockingstationen). Zuordnung im Asset unter <Link to="/assets">Assets</Link>.
      </p>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Bezeichnung</th>
              <th>Typ</th>
              <th>Inventar-Nr.</th>
              <th>Seriennr.</th>
              <th>Garantie</th>
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((a) => (
              <tr key={a.id}>
                <td>
                  {a.name}
                  {(a.manufacturer || a.model) && <div className="muted small">{[a.manufacturer, a.model].filter(Boolean).join(' ')}</div>}
                </td>
                <td>{TYPE_LABEL[a.type]}</td>
                <td>{a.inventoryNumber ?? '–'}</td>
                <td>{a.serialNumber ?? '–'}</td>
                <td>
                  <Warranty asset={a} />
                </td>
              </tr>
            ))}
            {list.data?.items.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  Keine Assets zugeordnet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
