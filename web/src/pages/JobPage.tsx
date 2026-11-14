import { Fragment, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, unwrap } from '../api/client';
import { useAuth } from '../auth';
import { TaskOutput } from '../components/TaskOutput';
import { fmtDate, useLoad } from '../hooks';
import { RunCounts, scheduleText, TRIGGER_LABEL } from './JobsPage';
import { DeleteButton } from './UsersPage';

export function JobPage() {
  const { id = '' } = useParams();
  const { can } = useAuth();
  const navigate = useNavigate();
  const job = useLoad(() => unwrap(api.GET('/jobs/{id}', { params: { path: { id } } })), [id]);
  const runs = useLoad(() => unwrap(api.GET('/jobs/{id}/runs', { params: { path: { id }, query: { limit: 50 } } })), [id]);
  const targets = useLoad(() => unwrap(api.GET('/jobs/{id}/targets', { params: { path: { id } } })), [id]);
  const [error, setError] = useState<string | null>(null);

  const j = job.data;
  if (job.error) return <div className="error">{job.error}</div>;
  if (!j) return <div className="muted">Lade …</div>;

  async function runNow() {
    setError(null);
    try {
      const run = await unwrap(api.POST('/jobs/{id}/run', { params: { path: { id } } }));
      navigate(`/runs/${run.id}`);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <>
      <div className="toolbar">
        <h1>
          <Link to="/jobs" className="muted">
            Jobs
          </Link>{' '}
          / {j.name}
        </h1>
        {can('jobs:execute') && <button onClick={() => void runNow()}>Jetzt ausführen</button>}
        {can('jobs:update') && (
          <Link className="button" to={`/jobs/${id}/edit`}>
            Bearbeiten
          </Link>
        )}
        {can('jobs:delete') && <DeleteButton onConfirm={() => unwrap(api.DELETE('/jobs/{id}', { params: { path: { id } } })).then(() => navigate('/jobs'))} />}
      </div>
      {error && <div className="error">{error}</div>}
      <div className="grid2">
        <div className="card">
          <h2>Ablauf</h2>
          <dl className="facts">
            <div>
              <dt>Auslöser</dt>
              <dd>{scheduleText(j)}</dd>
            </div>
            <div>
              <dt>Nächste Ausführung</dt>
              <dd>{fmtDate(j.nextRunAt)}</dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>{j.enabled ? 'aktiv' : 'deaktiviert'}</dd>
            </div>
            <div>
              <dt>Timeout / Wiederholungen</dt>
              <dd>
                {j.options.timeoutSeconds}s / {j.options.maxRetries}× (Pause {j.options.retryDelaySeconds}s)
              </dd>
            </div>
            <div>
              <dt>Wartungsfenster</dt>
              <dd>
                {j.options.maintenanceWindow
                  ? `${j.options.maintenanceWindow.days.map((d) => ['So', 'Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa'][d]).join(', ')} ${j.options.maintenanceWindow.start}–${j.options.maintenanceWindow.end}`
                  : '–'}
              </dd>
            </div>
          </dl>
          <h2>Schritte</h2>
          <ol>
            {j.steps.map((s) => (
              <li key={s.position}>
                <Link to={`/scripts/${s.scriptId}`}>{s.scriptName}</Link> v{s.version}{' '}
                {s.versionStatus !== 'approved' && <span className="badge danger">{s.versionStatus}</span>}
                {Object.keys(s.params).length > 0 && <span className="muted"> – {Object.entries(s.params).map(([k, v]) => `${k}=${String(v)}`).join(', ')}</span>}
                {s.continueOnError && <span className="muted"> (Fehler ignorieren)</span>}
              </li>
            ))}
          </ol>
        </div>
        <div className="card">
          <h2>Ziele ({targets.data?.total ?? '…'} Geräte)</h2>
          {j.targets.allDevices && <p>Alle Geräte</p>}
          <ul className="plain scroll-list">
            {targets.data?.items.map((d) => (
              <li key={d.id}>
                <Link to={`/devices/${d.id}`}>{d.hostname}</Link> <span className="muted">{d.os}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <h2>Ausführungen</h2>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Gestartet</th>
              <th>Auslöser</th>
              <th>Status</th>
              <th>Geräte</th>
              <th>Beendet</th>
            </tr>
          </thead>
          <tbody>
            {runs.data?.items.map((r) => (
              <tr key={r.id}>
                <td>
                  <Link to={`/runs/${r.id}`}>{fmtDate(r.createdAt)}</Link>
                </td>
                <td>{TRIGGER_LABEL[r.trigger] ?? r.trigger}</td>
                <td>{r.status}</td>
                <td>
                  <RunCounts counts={r.counts as Record<string, number>} />
                </td>
                <td>{fmtDate(r.finishedAt)}</td>
              </tr>
            ))}
            {runs.data?.items.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  Noch nicht ausgeführt.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

export function RunPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const { can } = useAuth();
  const run = useLoad(() => unwrap(api.GET('/runs/{id}', { params: { path: { id } } })), [id]);
  const tasks = useLoad(() => unwrap(api.GET('/runs/{id}/tasks', { params: { path: { id } } })), [id]);
  const [open, setOpen] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const r = run.data;
  if (run.error) return <div className="error">{run.error}</div>;
  if (!r) return <div className="muted">Lade …</div>;
  const mayExecute = can(r.jobId ? 'jobs:execute' : 'scripts:execute');
  const refresh = () => {
    void run.reload();
    void tasks.reload();
  };

  async function act(p: Promise<unknown>) {
    setError(null);
    try {
      await p;
      refresh();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <>
      <div className="toolbar">
        <h1>
          {r.jobId ? (
            <Link to={`/jobs/${r.jobId}`} className="muted">
              {r.name}
            </Link>
          ) : (
            <span className="muted">{r.name}</span>
          )}{' '}
          / Ausführung {fmtDate(r.createdAt)}
        </h1>
        <span className="badge">{r.status}</span>
        <button className="link" onClick={refresh}>
          Aktualisieren
        </button>
        {mayExecute && r.status === 'running' && (
          <button className="link danger" onClick={() => void act(unwrap(api.POST('/runs/{id}/cancel', { params: { path: { id } } })))}>
            Abbrechen
          </button>
        )}
        {mayExecute && r.status !== 'running' && (r.counts.failed || r.counts.timeout || r.counts.cancelled) ? (
          <button
            onClick={() =>
              void unwrap(api.POST('/runs/{id}/rerun', { params: { path: { id } }, body: { onlyFailed: true } }))
                .then((n) => navigate(`/runs/${n.id}`))
                .catch((e: Error) => setError(e.message))
            }
          >
            Fehlgeschlagene wiederholen
          </button>
        ) : null}
      </div>
      {error && <div className="error">{error}</div>}
      <p>
        <RunCounts counts={r.counts as Record<string, number>} /> · Schritte: {r.steps.map((s) => `${s.scriptName} v${s.version}`).join(' → ')}
      </p>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Gerät</th>
              <th>Status</th>
              <th>Versuch</th>
              <th>Exitcode</th>
              <th>Gestartet</th>
              <th>Beendet</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {tasks.data?.items.map((t) => (
              <Fragment key={t.id}>
                <tr>
                  <td>
                    <Link to={`/devices/${t.deviceId}`}>{t.hostname}</Link>
                  </td>
                  <td>
                    <span className={t.status === 'succeeded' ? 'badge ok' : ['failed', 'timeout'].includes(t.status) ? 'badge danger' : 'badge'}>{t.status}</span>
                    {t.error?.startsWith('integrity:') && (
                      <span className="badge danger" title="Inhalt oder Datei stimmte nicht mit dem beim Speichern berechneten SHA-256-Hash überein – nicht ausgeführt">
                        Hash-Prüfung fehlgeschlagen
                      </span>
                    )}
                    {t.cancelRequested && t.status === 'running' && <span className="muted"> (Abbruch angefordert)</span>}
                    {t.error && <div className="muted small">{t.error}</div>}
                  </td>
                  <td>{t.attempt}</td>
                  <td>{t.exitCode ?? '–'}</td>
                  <td>{fmtDate(t.startedAt)}</td>
                  <td>{fmtDate(t.finishedAt)}</td>
                  <td className="actions">
                    {t.status !== 'skipped' && (
                      <button className="link" onClick={() => setOpen(open === t.id ? null : t.id)}>
                        {open === t.id ? 'Ausgabe schließen' : 'Ausgabe'}
                      </button>
                    )}
                    {mayExecute && ['pending', 'dispatched', 'running'].includes(t.status) && !t.cancelRequested && (
                      <button className="link danger" onClick={() => void act(unwrap(api.POST('/tasks/{id}/cancel', { params: { path: { id: t.id } } })))}>
                        Abbrechen
                      </button>
                    )}
                  </td>
                </tr>
                {open === t.id && (
                  <tr key={`${t.id}-out`}>
                    <td colSpan={7}>
                      <TaskOutput taskId={t.id} onStatus={(s) => s !== t.status && ['succeeded', 'failed', 'timeout', 'cancelled'].includes(s) && refresh()} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
