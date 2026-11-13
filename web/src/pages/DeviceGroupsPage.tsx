import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api, unwrap, type Schemas } from '../api/client';
import { useAuth } from '../auth';
import { DevicePicker, FilterBuilder } from '../components/forms';
import { fmtRelative, OS_LABEL } from '../format';
import { useLoad } from '../hooks';
import { DeleteButton } from './UsersPage';

type Filter = Schemas['GroupFilter'];
const EMPTY_FILTER: Filter = { match: 'all', rules: [{ field: 'os', op: 'eq', value: 'windows' }] };

export function DeviceGroupsPage() {
  const { can } = useAuth();
  const groups = useLoad(() => unwrap(api.GET('/device-groups')));
  const fields = useLoad(() => unwrap(api.GET('/custom-fields')));
  const [kind, setKind] = useState<'static' | 'dynamic' | null>(null);
  const [name, setName] = useState('');
  const [deviceIds, setDeviceIds] = useState<string[]>([]);
  const [filter, setFilter] = useState<Filter>(EMPTY_FILTER);
  const [preview, setPreview] = useState<{ total: number; items: { hostname: string }[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function create() {
    setError(null);
    try {
      await unwrap(api.POST('/device-groups', { body: kind === 'static' ? { kind: 'static', name, deviceIds } : { kind: 'dynamic', name, filter } }));
      setKind(null);
      setName('');
      setDeviceIds([]);
      setFilter(EMPTY_FILTER);
      setPreview(null);
      await groups.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function runPreview() {
    setError(null);
    try {
      setPreview(await unwrap(api.POST('/device-groups/preview', { body: { filter } })));
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <>
      <div className="toolbar">
        <h1>Gerätegruppen</h1>
        {can('device_groups:create') && (
          <>
            <button onClick={() => setKind('static')}>Statische Gruppe</button>
            <button onClick={() => setKind('dynamic')}>Dynamische Gruppe</button>
          </>
        )}
      </div>
      {error && <div className="error">{error}</div>}
      {kind && (
        <div className="card">
          <h2>{kind === 'static' ? 'Neue statische Gruppe' : 'Neue dynamische Gruppe'}</h2>
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          {kind === 'static' ? (
            <DevicePicker selected={deviceIds} onChange={setDeviceIds} />
          ) : (
            <>
              <FilterBuilder filter={filter} onChange={setFilter} customFields={fields.data?.items ?? []} />
              <button className="link" onClick={() => void runPreview()}>
                Vorschau
              </button>
              {preview && (
                <p className="muted">
                  {preview.total} Geräte: {preview.items.map((d) => d.hostname).join(', ')}
                  {preview.total > preview.items.length && ' …'}
                </p>
              )}
            </>
          )}
          <p>
            <button disabled={!name} onClick={() => void create()}>
              Anlegen
            </button>{' '}
            <button className="link" onClick={() => setKind(null)}>
              Abbrechen
            </button>
          </p>
        </div>
      )}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Art</th>
              <th>Geräte</th>
            </tr>
          </thead>
          <tbody>
            {groups.data?.items.map((g) => (
              <tr key={g.id}>
                <td>
                  <Link to={`/device-groups/${g.id}`}>{g.name}</Link>
                </td>
                <td>{g.kind === 'dynamic' ? 'dynamisch' : 'statisch'}</td>
                <td>{g.memberCount}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

export function DeviceGroupPage() {
  const { id = '' } = useParams();
  const { can } = useAuth();
  const group = useLoad(() => unwrap(api.GET('/device-groups/{id}', { params: { path: { id } } })), [id]);
  const members = useLoad(() => unwrap(api.GET('/device-groups/{id}/devices', { params: { path: { id }, query: { limit: 500 } } })), [id]);
  const fields = useLoad(() => unwrap(api.GET('/custom-fields')));
  const [filter, setFilter] = useState<Filter | null>(null);
  const [picking, setPicking] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const g = group.data;
  if (group.error) return <div className="error">{group.error}</div>;
  if (!g) return <div className="muted">Lade …</div>;

  async function act(p: Promise<unknown>) {
    setError(null);
    try {
      await p;
      setFilter(null);
      setPicking(null);
      await group.reload();
      await members.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <>
      <div className="toolbar">
        <h1>
          <Link to="/device-groups" className="muted">
            Gerätegruppen
          </Link>{' '}
          / {g.name}
        </h1>
        <span className="badge">{g.kind === 'dynamic' ? 'dynamisch' : 'statisch'}</span>
        {can('device_groups:update') && g.kind === 'dynamic' && !filter && <button onClick={() => setFilter(g.filter as Filter)}>Filter bearbeiten</button>}
        {can('device_groups:update') && g.kind === 'static' && !picking && <button onClick={() => setPicking((members.data?.items ?? []).map((d) => d.id))}>Mitglieder bearbeiten</button>}
        {can('device_groups:delete') && <DeleteButton onConfirm={() => act(unwrap(api.DELETE('/device-groups/{id}', { params: { path: { id } } }))).then(() => history.back())} />}
      </div>
      {error && <div className="error">{error}</div>}
      {filter && (
        <div className="card">
          <FilterBuilder filter={filter} onChange={setFilter} customFields={fields.data?.items ?? []} />
          <button onClick={() => void act(unwrap(api.PATCH('/device-groups/{id}', { params: { path: { id } }, body: { filter } })))}>Speichern</button>{' '}
          <button className="link" onClick={() => setFilter(null)}>
            Abbrechen
          </button>
        </div>
      )}
      {picking && (
        <div className="card">
          <DevicePicker selected={picking} onChange={setPicking} />
          <button onClick={() => void act(unwrap(api.PUT('/device-groups/{id}/members', { params: { path: { id } }, body: { deviceIds: picking } })))}>Speichern</button>{' '}
          <button className="link" onClick={() => setPicking(null)}>
            Abbrechen
          </button>
        </div>
      )}
      <h2>{g.memberCount} Geräte</h2>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Betriebssystem</th>
              <th>Angemeldet</th>
              <th>Letzter Kontakt</th>
            </tr>
          </thead>
          <tbody>
            {members.data?.items.map((d) => (
              <tr key={d.id}>
                <td>
                  <Link to={`/devices/${d.id}`}>{d.hostname}</Link>
                </td>
                <td>
                  {OS_LABEL[d.os]} <span className="muted">{d.osVersion}</span>
                </td>
                <td>{d.loggedOnUser ?? '–'}</td>
                <td>{fmtRelative(d.lastSeenAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

export function CustomFieldsPage() {
  const { can } = useAuth();
  const fields = useLoad(() => unwrap(api.GET('/custom-fields')));
  const [form, setForm] = useState({ name: '', label: '', type: 'string' as 'string' | 'number' | 'boolean' | 'date' });
  const [error, setError] = useState<string | null>(null);
  return (
    <>
      <h1>Eigene Inventarfelder</h1>
      <p className="muted">
        Werte werden manuell am Gerät gepflegt oder per Job-Schritt („Ausgabe in Feld speichern“: letzte Zeile der Skriptausgabe) gesammelt. In dynamischen Gruppen als{' '}
        <code>custom:&lt;name&gt;</code> filterbar.
      </p>
      {error && <div className="error">{error}</div>}
      {can('settings:update') && (
        <form
          className="card form-inline"
          onSubmit={(e) => {
            e.preventDefault();
            void unwrap(api.POST('/custom-fields', { body: form }))
              .then(() => {
                setForm({ name: '', label: '', type: 'string' });
                return fields.reload();
              })
              .catch((err: Error) => setError(err.message));
          }}
        >
          <input placeholder="name (a-z, 0-9, _)" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          <input placeholder="Bezeichnung" value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} required />
          <select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value as typeof form.type })}>
            <option value="string">Text</option>
            <option value="number">Zahl</option>
            <option value="boolean">Ja/Nein</option>
            <option value="date">Datum</option>
          </select>
          <button type="submit">Feld anlegen</button>
        </form>
      )}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Bezeichnung</th>
              <th>Name</th>
              <th>Typ</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {fields.data?.items.map((f) => (
              <tr key={f.id}>
                <td>{f.label}</td>
                <td>
                  <code>custom:{f.name}</code>
                </td>
                <td>{f.type}</td>
                <td className="actions">
                  {can('settings:update') && (
                    <DeleteButton onConfirm={() => unwrap(api.DELETE('/custom-fields/{id}', { params: { path: { id: f.id } } })).then(() => fields.reload())} />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
