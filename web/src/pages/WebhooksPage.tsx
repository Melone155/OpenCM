import { Fragment, useState } from 'react';
import { api, unwrap, type Schemas } from '../api/client';
import { useAuth } from '../auth';
import { fmtDate, useLoad } from '../hooks';
import { DeleteButton } from './UsersPage';

type Hook = Schemas['Webhook'];
type Form = { id?: string; name: string; url: string; events: string[]; enabled: boolean };

export function WebhooksPage() {
  const { can } = useAuth();
  const hooks = useLoad(() => unwrap(api.GET('/webhooks')));
  const events = useLoad(() => unwrap(api.GET('/webhook-events')));
  const [form, setForm] = useState<Form | null>(null);
  const [secret, setSecret] = useState<{ name: string; secret: string } | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  async function act<T>(fn: () => Promise<T>, done?: string) {
    setError(null);
    setMsg(null);
    try {
      const r = await fn();
      if (done) setMsg(done);
      await hooks.reload();
      return r;
    } catch (e) {
      setError((e as Error).message);
      return null;
    }
  }

  async function save() {
    if (!form) return;
    const body = { name: form.name, url: form.url, events: form.events, enabled: form.enabled };
    const r = form.id
      ? await act(() => unwrap(api.PATCH('/webhooks/{id}', { params: { path: { id: form.id! } }, body })), 'Gespeichert.')
      : await act(() => unwrap(api.POST('/webhooks', { body })));
    if (r) {
      if (!form.id && r.secret) setSecret({ name: r.name, secret: r.secret });
      setForm(null);
    }
  }

  return (
    <>
      <div className="toolbar">
        <h1>Webhooks</h1>
        {can('webhooks:create') && <button onClick={() => setForm({ name: '', url: 'https://', events: [], enabled: true })}>Neuer Webhook</button>}
      </div>
      <p className="muted">
        OpenCM meldet Ereignisse per HTTPS-POST an andere Systeme (Ticketsystem, Chat, SIEM). Jede Nachricht ist signiert: Header <code>X-OpenCM-Signature: sha256=HMAC(Geheimnis, X-OpenCM-Timestamp + "." + Body)</code>.
        Fehlgeschlagene Zustellungen werden bis zu sechsmal wiederholt (1 min bis 6 h).
      </p>
      {msg && <div className="card">{msg}</div>}
      {error && <div className="error">{error}</div>}
      {secret && (
        <div className="card highlight">
          <strong>Geheimnis für „{secret.name}“ – wird nur jetzt angezeigt:</strong>
          <pre className="code secret">{secret.secret}</pre>
          <button className="link" onClick={() => setSecret(null)}>
            Notiert, ausblenden
          </button>
        </div>
      )}
      {form && (
        <div className="card highlight">
          <h2>{form.id ? 'Webhook bearbeiten' : 'Neuer Webhook'}</h2>
          <div className="form-grid">
            <label>
              Name
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </label>
            <label>
              URL (https)
              <input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} />
            </label>
          </div>
          <label className="check">
            <input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} /> aktiv
          </label>
          <h3>Ereignisse</h3>
          <div className="check-grid">
            <label className="check">
              <input type="checkbox" checked={form.events.includes('*')} onChange={(e) => setForm({ ...form, events: e.target.checked ? ['*'] : [] })} /> <strong>alle</strong>
            </label>
            {!form.events.includes('*') &&
              events.data?.items
                .filter((ev) => ev.name !== 'webhook.test')
                .map((ev) => (
                  <label key={ev.name} className="check" title={ev.name}>
                    <input
                      type="checkbox"
                      checked={form.events.includes(ev.name)}
                      onChange={(e) => setForm({ ...form, events: e.target.checked ? [...form.events, ev.name] : form.events.filter((x) => x !== ev.name) })}
                    />
                    {ev.label}
                  </label>
                ))}
          </div>
          <p>
            <button disabled={!form.name.trim() || !form.events.length} onClick={() => void save()}>
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
              <th>Webhook</th>
              <th>Ereignisse</th>
              <th>Letzte Zustellung</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {hooks.data?.items.map((h: Hook) => (
              <Fragment key={h.id}>
                <tr>
                  <td>
                    {h.name} {!h.enabled && <span className="badge">inaktiv</span>}
                    <div className="muted small">{h.url}</div>
                  </td>
                  <td className="small">{h.events.includes('*') ? 'alle' : h.events.join(', ')}</td>
                  <td>
                    {h.lastDelivery ? (
                      <>
                        <span className={h.lastDelivery.status === 'succeeded' ? 'badge ok' : h.lastDelivery.status === 'failed' ? 'badge danger' : 'badge'}>{h.lastDelivery.status}</span>{' '}
                        <span className="small">{h.lastDelivery.event}</span>
                        {h.lastDelivery.lastError && <div className="error-text small">{h.lastDelivery.lastError}</div>}
                        <div className="muted small">{fmtDate(h.lastDelivery.createdAt)}</div>
                      </>
                    ) : (
                      '–'
                    )}
                  </td>
                  <td className="actions">
                    {can('webhooks:update') && (
                      <button className="link" onClick={() => void act(() => unwrap(api.POST('/webhooks/{id}/test', { params: { path: { id: h.id } } })).then((d) => setMsg(d.status === 'succeeded' ? `Test erfolgreich (HTTP ${d.responseStatus}).` : `Test fehlgeschlagen: ${d.lastError}`)))}>
                        Testen
                      </button>
                    )}
                    <button className="link" onClick={() => setOpen(open === h.id ? null : h.id)}>
                      Protokoll
                    </button>
                    {can('webhooks:update') && (
                      <button className="link" onClick={() => setForm({ id: h.id, name: h.name, url: h.url, events: h.events, enabled: h.enabled })}>
                        Bearbeiten
                      </button>
                    )}
                    {can('webhooks:update') && (
                      <button
                        className="link"
                        onClick={() =>
                          void act(() => unwrap(api.PATCH('/webhooks/{id}', { params: { path: { id: h.id } }, body: { rotateSecret: true } })).then((r) => r.secret && setSecret({ name: r.name, secret: r.secret })))
                        }
                      >
                        Neues Geheimnis
                      </button>
                    )}
                    {can('webhooks:delete') && <DeleteButton onConfirm={() => act(() => unwrap(api.DELETE('/webhooks/{id}', { params: { path: { id: h.id } } })))} />}
                  </td>
                </tr>
                {open === h.id && (
                  <tr key={`${h.id}-log`}>
                    <td colSpan={4}>
                      <Deliveries id={h.id} mayRedeliver={can('webhooks:update')} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {hooks.data?.items.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  Noch keine Webhooks.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Deliveries({ id, mayRedeliver }: { id: string; mayRedeliver: boolean }) {
  const list = useLoad(() => unwrap(api.GET('/webhooks/{id}/deliveries', { params: { path: { id }, query: { limit: 50 } } })), [id]);
  return (
    <table className="small">
      <thead>
        <tr>
          <th>Zeit</th>
          <th>Ereignis</th>
          <th>Status</th>
          <th>Versuche</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {list.data?.items.map((d) => (
          <tr key={d.id}>
            <td>{fmtDate(d.createdAt)}</td>
            <td>{d.event}</td>
            <td>
              <span className={d.status === 'succeeded' ? 'badge ok' : d.status === 'failed' ? 'badge danger' : 'badge'}>{d.status}</span> {d.responseStatus && `HTTP ${d.responseStatus}`}
              {d.lastError && <div className="error-text">{d.lastError}</div>}
            </td>
            <td>{d.attempts}</td>
            <td>
              {mayRedeliver && d.status !== 'pending' && (
                <button className="link" onClick={() => void unwrap(api.POST('/webhook-deliveries/{id}/redeliver', { params: { path: { id: d.id } } })).then(() => list.reload())}>
                  Erneut senden
                </button>
              )}
            </td>
          </tr>
        ))}
        {list.data?.items.length === 0 && (
          <tr>
            <td colSpan={5} className="muted">
              Noch keine Zustellungen.
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}
