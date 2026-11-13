import { Link } from 'react-router-dom';
import { api, unwrap, type Schemas } from '../api/client';
import { useAuth } from '../auth';
import { fmtDate, useLoad } from '../hooks';

export const TRIGGER_LABEL: Record<string, string> = {
  manual: 'manuell',
  once: 'einmalig',
  cron: 'wiederkehrend',
  agent_start: 'bei Agent-Start',
  user_login: 'bei Benutzer-Login',
  test: 'Testlauf',
  rerun: 'Wiederholung',
};

export function scheduleText(j: Pick<Schemas['Job'], 'trigger' | 'cron' | 'runAt' | 'timezone' | 'nextRunAt'>): string {
  switch (j.trigger) {
    case 'cron':
      return `${j.cron} (${j.timezone})`;
    case 'once':
      return fmtDate(j.runAt);
    default:
      return TRIGGER_LABEL[j.trigger] ?? j.trigger;
  }
}

export function RunCounts({ counts }: { counts: Record<string, number> }) {
  const order: [string, string][] = [
    ['succeeded', 'ok'],
    ['failed', 'danger'],
    ['timeout', 'danger'],
    ['running', ''],
    ['dispatched', ''],
    ['pending', ''],
    ['cancelled', ''],
    ['skipped', ''],
  ];
  return (
    <span className="counts">
      {order
        .filter(([k]) => counts[k])
        .map(([k, cls]) => (
          <span key={k} className={`badge ${cls}`} title={k}>
            {k} {counts[k]}
          </span>
        ))}
    </span>
  );
}

export function JobsPage() {
  const { can } = useAuth();
  const jobs = useLoad(() => unwrap(api.GET('/jobs')));
  return (
    <>
      <div className="toolbar">
        <h1>Jobs</h1>
        <Link to="/runs" className="muted">
          Aktivität
        </Link>
        {can('jobs:create') && (
          <Link className="button" to="/jobs/new">
            Neuer Job
          </Link>
        )}
      </div>
      {jobs.error && <div className="error">{jobs.error}</div>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Auslöser</th>
              <th>Schritte</th>
              <th>Nächste Ausführung</th>
              <th>Zuletzt</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {jobs.data?.items.map((j) => (
              <tr key={j.id}>
                <td>
                  <Link to={`/jobs/${j.id}`}>{j.name}</Link>
                </td>
                <td>{scheduleText(j)}</td>
                <td>{j.stepCount}</td>
                <td>{fmtDate(j.nextRunAt)}</td>
                <td>{fmtDate(j.lastRunAt)}</td>
                <td>{j.enabled ? <span className="badge ok">aktiv</span> : <span className="badge">deaktiviert</span>}</td>
              </tr>
            ))}
            {jobs.data?.items.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  Noch keine Jobs. Jobs verwenden freigegebene Skripte.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

export function RunsPage() {
  const runs = useLoad(() => unwrap(api.GET('/runs', { params: { query: { limit: 100 } } })));
  return (
    <>
      <h1>Aktivität</h1>
      {runs.error && <div className="error">{runs.error}</div>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Gestartet</th>
              <th>Name</th>
              <th>Auslöser</th>
              <th>Status</th>
              <th>Geräte</th>
            </tr>
          </thead>
          <tbody>
            {runs.data?.items.map((r) => (
              <tr key={r.id}>
                <td>{fmtDate(r.createdAt)}</td>
                <td>
                  <Link to={`/runs/${r.id}`}>{r.name}</Link>
                </td>
                <td>{TRIGGER_LABEL[r.trigger] ?? r.trigger}</td>
                <td>{r.status}</td>
                <td>
                  <RunCounts counts={r.counts as Record<string, number>} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
