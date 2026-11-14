import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api, unwrap, type Schemas } from '../api/client';
import { useAuth } from '../auth';
import { fmtDate, useLoad } from '../hooks';

export const DEPLOYMENT_STATUS: Record<string, string> = {
  created: 'angelegt',
  running: 'läuft',
  paused: 'angehalten',
  completed: 'abgeschlossen',
  cancelled: 'abgebrochen',
};
const statusClass = (s: string) => (s === 'completed' ? 'badge ok' : s === 'paused' ? 'badge warn' : s === 'cancelled' ? 'badge danger' : 'badge');

/** POST /deployments; returns the deployment id. */
export async function startDeployment(body: Schemas['DeploymentInput']): Promise<{ id: string }> {
  const r = await unwrap(api.POST('/deployments', { body }));
  return { id: r.id };
}

export function DeploymentsPage() {
  const [kind, setKind] = useState<'' | 'package' | 'os_updates'>('');
  const list = useLoad(() => unwrap(api.GET('/deployments', { params: { query: { kind: kind || undefined, limit: 200 } } })), [kind]);
  return (
    <>
      <div className="toolbar">
        <h1>Verteilungen</h1>
        <select value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
          <option value="">alle</option>
          <option value="package">Softwarepakete</option>
          <option value="os_updates">Betriebssystem-Updates</option>
        </select>
        <button className="link" onClick={() => void list.reload()}>
          Aktualisieren
        </button>
      </div>
      {list.error && <div className="error">{list.error}</div>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Verteilung</th>
              <th>Status</th>
              <th>Ring</th>
              <th>Fortschritt</th>
              <th>Gestartet</th>
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((d) => (
              <tr key={d.id}>
                <td>
                  <Link to={`/deployments/${d.id}`}>{d.name}</Link>
                  <div className="muted small">{d.kind === 'os_updates' ? 'Betriebssystem-Updates' : d.action === 'install' ? 'Installation' : 'Deinstallation'}</div>
                </td>
                <td>
                  <span className={statusClass(d.status)}>{DEPLOYMENT_STATUS[d.status] ?? d.status}</span>
                </td>
                <td>{d.currentRing >= 0 ? `${d.currentRing + 1}/${d.ringCount} ${d.currentRingName ?? ''}` : `–/${d.ringCount}`}</td>
                <td>
                  <Progress total={d.progress.total} ok={d.progress.succeeded} failed={d.progress.failed} />
                </td>
                <td>{fmtDate(d.createdAt)}</td>
              </tr>
            ))}
            {list.data?.items.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  Noch keine Verteilungen. Pakete werden unter Software → Paket → „Verteilen …“ verteilt, Updates unter Patches.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

export function Progress({ total, ok, failed }: { total: number; ok: number; failed: number }) {
  if (!total) return <span className="muted">–</span>;
  const p = (n: number) => `${(n / total) * 100}%`;
  return (
    <span className="progress" title={`${ok} erfolgreich, ${failed} fehlgeschlagen, ${total - ok - failed} offen`}>
      <span className="progress-bar">
        <span className="progress-ok" style={{ width: p(ok) }} />
        <span className="progress-failed" style={{ width: p(failed) }} />
      </span>
      <span className="small">
        {ok}/{total}
        {failed ? <span className="error-text"> · {failed} Fehler</span> : null}
      </span>
    </span>
  );
}

export function DeploymentPage() {
  const { id = '' } = useParams();
  const { can } = useAuth();
  const dep = useLoad(() => unwrap(api.GET('/deployments/{id}', { params: { path: { id } } })), [id]);
  const [error, setError] = useState<string | null>(null);

  // refresh while something is happening
  const d = dep.data;
  useEffect(() => {
    if (!d || d.status !== 'running') return;
    const t = setInterval(() => void dep.reload(), 5000);
    return () => clearInterval(t);
  }, [d?.status, dep.reload]); // eslint-disable-line react-hooks/exhaustive-deps

  if (dep.error) return <div className="error">{dep.error}</div>;
  if (!d) return <div className="muted">Lade …</div>;
  const mayExec = can(d.kind === 'os_updates' ? 'patches:execute' : 'software:execute');
  const cur = d.rings[d.currentRing];
  const curDone = !!cur?.stats.finished;

  async function control(action: 'promote' | 'pause' | 'resume' | 'cancel') {
    setError(null);
    try {
      const path = `/deployments/{id}/${action}` as '/deployments/{id}/promote';
      await unwrap(api.POST(path, { params: { path: { id } } }));
      await dep.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <>
      <div className="toolbar">
        <h1>
          <Link to="/deployments" className="muted">
            Verteilungen
          </Link>{' '}
          / {d.name}
        </h1>
        <span className={statusClass(d.status)}>{DEPLOYMENT_STATUS[d.status] ?? d.status}</span>
        {mayExec && ['running', 'paused'].includes(d.status) && curDone && (
          <button onClick={() => void control('promote')}>{d.currentRing >= d.rings.length - 1 ? 'Abschließen' : 'Nächsten Ring jetzt starten'}</button>
        )}
        {mayExec && d.status === 'running' && (
          <button className="link" onClick={() => void control('pause')}>
            Anhalten
          </button>
        )}
        {mayExec && d.status === 'paused' && (
          <button className="link" onClick={() => void control('resume')}>
            Fortsetzen
          </button>
        )}
        {mayExec && !['completed', 'cancelled'].includes(d.status) && (
          <button className="link danger" onClick={() => void control('cancel')}>
            Abbrechen
          </button>
        )}
      </div>
      {error && <div className="error">{error}</div>}
      {d.pausedReason && d.status !== 'completed' && (
        <div className={d.pausedReason.includes('integrity:') ? 'error' : 'card'}>
          {d.pausedReason.includes('integrity:') && <strong>Hash-Prüfung fehlgeschlagen – </strong>}
          {d.pausedReason}
        </div>
      )}
      <dl className="facts">
        <div>
          <dt>Inhalt</dt>
          <dd>
            {d.package ? (
              <>
                <Link to={`/packages/${d.package.packageId}`}>
                  {d.package.name} {d.package.version}
                </Link>{' '}
                – {d.action === 'install' ? 'Installation' : 'Deinstallation'}
              </>
            ) : (
              <>
                Betriebssystem-Updates: {d.patchFilter?.include?.length ? `${d.patchFilter.include.length} ausgewählte` : { critical: 'kritische', security: 'Sicherheitsupdates', all: 'alle' }[d.patchFilter?.classification ?? 'security']}
                {d.patchFilter?.reboot === 'if_required' ? ', Neustart bei Bedarf (5 min Vorwarnung)' : ', kein automatischer Neustart'}
              </>
            )}
          </dd>
        </div>
        <div>
          <dt>Plattformen</dt>
          <dd>{d.platforms.join(', ')}</dd>
        </div>
        <div>
          <dt>Angelegt</dt>
          <dd>
            {fmtDate(d.createdAt)} {d.createdByName && `von ${d.createdByName}`}
          </dd>
        </div>
        {d.finishedAt && (
          <div>
            <dt>Beendet</dt>
            <dd>{fmtDate(d.finishedAt)}</dd>
          </div>
        )}
      </dl>

      <h2>Ringe</h2>
      <div className="rings">
        {d.rings.map((r, i) => {
          const s = r.stats;
          const active = i === d.currentRing && !['completed', 'cancelled'].includes(d.status);
          return (
            <div key={i} className={`card ring ${active ? 'highlight' : ''} ${s.started ? '' : 'muted'}`}>
              <div className="toolbar">
                <h3>
                  {i + 1}. {r.name}
                </h3>
                {s.started ? s.finished ? <span className={s.successPercent >= (r.minSuccessPercent ?? 90) ? 'badge ok' : 'badge danger'}>{s.successPercent} %</span> : <span className="badge">läuft</span> : <span className="badge">wartet</span>}
              </div>
              <p className="small">
                Ziel: {r.targets.allDevices ? 'alle Geräte' : [...r.groupNames, ...(r.targets.deviceIds?.length ? [`${r.targets.deviceIds.length} Gerät(e)`] : [])].join(', ')}
              </p>
              {i < d.rings.length - 1 && (
                <p className="muted small">
                  weiter nach {r.delayHours ?? 0} h bei ≥ {r.minSuccessPercent ?? 90} % Erfolg
                </p>
              )}
              {s.started && <Progress total={s.total - s.skipped} ok={s.succeeded} failed={s.failed} />}
              {s.skipped > 0 && <p className="muted small">{s.skipped} übersprungen</p>}
              {d.runs
                .filter((run) => run.ring === i)
                .map((run) => (
                  <div key={run.id} className="small">
                    <Link to={`/runs/${run.id}`}>{run.name}</Link>
                  </div>
                ))}
            </div>
          );
        })}
      </div>
    </>
  );
}
