import { Fragment, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, unwrap, type Schemas } from '../api/client';
import { useAuth } from '../auth';
import { useLoad } from '../hooks';
import { DeleteButton } from './UsersPage';

type License = Schemas['License'];
type Form = { id?: string; name: string; vendor: string; softwarePattern: string; publisherPattern: string; seats: number; expiresAt: string; cost: string; notes: string };
const empty: Form = { name: '', vendor: '', softwarePattern: '', publisherPattern: '', seats: 1, expiresAt: '', cost: '', notes: '' };

/** Software license management (third-party software owned by the organisation). */
export function LicensesPage() {
  const { can } = useAuth();
  const list = useLoad(() => unwrap(api.GET('/licenses')));
  const [form, setForm] = useState<Form | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    if (!form) return;
    setError(null);
    const body = {
      name: form.name,
      vendor: form.vendor,
      softwarePattern: form.softwarePattern,
      publisherPattern: form.publisherPattern.trim() || null,
      seats: form.seats,
      expiresAt: form.expiresAt || null,
      cost: form.cost ? Number(form.cost) : null,
      notes: form.notes,
    };
    try {
      if (form.id) await unwrap(api.PATCH('/licenses/{id}', { params: { path: { id: form.id } }, body }));
      else await unwrap(api.POST('/licenses', { body }));
      setForm(null);
      await list.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const edit = (l: License) =>
    setForm({ id: l.id, name: l.name, vendor: l.vendor, softwarePattern: l.softwarePattern, publisherPattern: l.publisherPattern ?? '', seats: l.seats, expiresAt: l.expiresAt ?? '', cost: l.cost ?? '', notes: l.notes ?? '' });

  return (
    <>
      <div className="toolbar">
        <h1>Softwarelizenzen</h1>
        {can('licenses:create') && <button onClick={() => setForm({ ...empty })}>Lizenz erfassen</button>}
      </div>
      <p className="muted">
        Erfassen Sie, wie viele Lizenzen Ihre Organisation für eine Software besitzt. OpenCM zählt anhand des Inventars, auf wie vielen Geräten sie installiert ist, und meldet Überschreitungen und ablaufende Verträge. (OpenCM selbst ist Open Source unter MIT-Lizenz und unbeschränkt nutzbar.)
      </p>
      {error && <div className="error">{error}</div>}
      {form && (
        <div className="card highlight">
          <div className="form-grid">
            <label>
              Bezeichnung
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Microsoft 365 Apps – Volumenlizenz" />
            </label>
            <label>
              Hersteller
              <input value={form.vendor} onChange={(e) => setForm({ ...form, vendor: e.target.value })} />
            </label>
            <label>
              Software-Muster (Platzhalter *)
              <input value={form.softwarePattern} onChange={(e) => setForm({ ...form, softwarePattern: e.target.value })} placeholder="Microsoft 365 Apps*" />
            </label>
            <label>
              Herausgeber-Muster (optional)
              <input value={form.publisherPattern} onChange={(e) => setForm({ ...form, publisherPattern: e.target.value })} placeholder="Microsoft Corporation" />
            </label>
            <label>
              Anzahl Lizenzen
              <input type="number" min={0} value={form.seats} onChange={(e) => setForm({ ...form, seats: Number(e.target.value) })} />
            </label>
            <label>
              Läuft ab
              <input type="date" value={form.expiresAt} onChange={(e) => setForm({ ...form, expiresAt: e.target.value })} />
            </label>
            <label>
              Kosten (optional)
              <input type="number" min={0} step="0.01" value={form.cost} onChange={(e) => setForm({ ...form, cost: e.target.value })} />
            </label>
            <label>
              Notiz
              <input value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
            </label>
          </div>
          <p>
            <button disabled={!form.name.trim() || !form.softwarePattern.trim()} onClick={() => void save()}>
              Speichern
            </button>{' '}
            <button className="link" onClick={() => setForm(null)}>
              Abbrechen
            </button>
          </p>
        </div>
      )}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Lizenz</th>
              <th>Nutzung</th>
              <th>Status</th>
              <th>Läuft ab</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((l) => (
              <Fragment key={l.id}>
                <tr>
                  <td>
                    {l.name}
                    <div className="muted small">
                      {l.vendor && `${l.vendor} · `}
                      <code>{l.softwarePattern}</code>
                    </div>
                  </td>
                  <td>
                    <span className="progress">
                      <span className="progress-bar">
                        <span className={l.overused ? 'progress-failed' : 'progress-ok'} style={{ width: `${Math.min(100, l.seats ? (l.used / l.seats) * 100 : 100)}%` }} />
                      </span>
                      <span className="small">
                        {l.used} / {l.seats}
                      </span>
                    </span>
                  </td>
                  <td>
                    {l.overused ? <span className="badge danger">überschritten um {l.used - l.seats}</span> : <span className="badge ok">{l.available} frei</span>}
                  </td>
                  <td>
                    {l.expiresAt ? (
                      <>
                        {new Date(`${l.expiresAt}T00:00:00Z`).toLocaleDateString('de-DE', { timeZone: 'UTC' })}
                        {l.expired && <span className="badge danger"> abgelaufen</span>}
                        {l.expiringSoon && <span className="badge warn"> in {l.daysToExpiry} Tagen</span>}
                      </>
                    ) : (
                      '–'
                    )}
                  </td>
                  <td className="actions">
                    <button className="link" onClick={() => setOpen(open === l.id ? null : l.id)}>
                      Geräte
                    </button>
                    {can('licenses:update') && (
                      <button className="link" onClick={() => edit(l)}>
                        Bearbeiten
                      </button>
                    )}
                    {can('licenses:delete') && <DeleteButton onConfirm={() => unwrap(api.DELETE('/licenses/{id}', { params: { path: { id: l.id } } })).then(() => list.reload())} />}
                  </td>
                </tr>
                {open === l.id && (
                  <tr key={`${l.id}-dev`}>
                    <td colSpan={5}>
                      <LicenseDevices id={l.id} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {list.data?.items.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  Noch keine Lizenzen erfasst.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

function LicenseDevices({ id }: { id: string }) {
  const d = useLoad(() => unwrap(api.GET('/licenses/{id}', { params: { path: { id } } })), [id]);
  if (!d.data) return <span className="muted">Lade …</span>;
  return (
    <ul className="plain scroll-list small">
      {d.data.devices.map((x) => (
        <li key={x.deviceId}>
          <Link to={`/devices/${x.deviceId}`}>{x.hostname}</Link> – {x.software} {x.version}
        </li>
      ))}
      {d.data.devices.length === 0 && <li className="muted">Auf keinem Gerät gefunden.</li>}
    </ul>
  );
}
