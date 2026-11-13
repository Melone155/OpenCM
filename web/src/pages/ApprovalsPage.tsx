import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, unwrap } from '../api/client';
import { fmtDate, useLoad } from '../hooks';

const STATUS: Record<string, string> = { pending: 'offen', approved: 'freigegeben', rejected: 'abgelehnt', expired: 'abgelaufen', failed: 'fehlgeschlagen' };

export function ApprovalsPage() {
  const [status, setStatus] = useState<'pending' | 'all'>('pending');
  const list = useLoad(() => unwrap(api.GET('/approvals', { params: { query: { status, limit: 200 } } })), [status]);
  const [reason, setReason] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  async function decide(id: string, approve: boolean) {
    setError(null);
    try {
      const body = { reason: reason[id] || undefined };
      const r = approve
        ? await unwrap(api.POST('/approvals/{id}/approve', { params: { path: { id } }, body }))
        : await unwrap(api.POST('/approvals/{id}/reject', { params: { path: { id } }, body: { reason: reason[id] ?? '' } }));
      if (r.status === 'failed') setError(`Freigegeben, aber nicht ausgeführt: ${String((r.result as { error?: string } | null)?.error ?? '')}`);
      await list.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <>
      <div className="toolbar">
        <h1>Freigaben (Vier-Augen-Prinzip)</h1>
        <select value={status} onChange={(e) => setStatus(e.target.value as typeof status)}>
          <option value="pending">offen</option>
          <option value="all">alle</option>
        </select>
      </div>
      <p className="muted">
        Massenaktionen (z. B. Jobs auf „Alle Geräte“ oder über der Geräte-Schwelle) werden erst ausgeführt, wenn eine zweite Person zustimmt – mit <code>jobs:approve</code> (Jobs, Skripte), <code>software:approve</code> (Softwareverteilung) bzw. <code>patches:approve</code> (Updates).
      </p>
      {error && <div className="error">{error}</div>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Angefragt</th>
              <th>Aktion</th>
              <th>Geräte</th>
              <th>Von</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((a) => {
              const result = a.result as { runId?: string; jobId?: string; deploymentId?: string; error?: string } | null | undefined;
              return (
                <tr key={a.id}>
                  <td>
                    {fmtDate(a.requestedAt)}
                    <div className="muted small">läuft ab {fmtDate(a.expiresAt)}</div>
                  </td>
                  <td>{a.summary}</td>
                  <td>{a.deviceCount}</td>
                  <td>{a.requesterName ?? '–'}</td>
                  <td>
                    <span className={a.status === 'approved' ? 'badge ok' : ['rejected', 'failed'].includes(a.status) ? 'badge danger' : 'badge'}>{STATUS[a.status]}</span>
                    {a.reason && <div className="muted small">{a.reason}</div>}
                    {result?.runId && (
                      <div className="small">
                        <Link to={`/runs/${result.runId}`}>zur Ausführung</Link>
                      </div>
                    )}
                    {result?.deploymentId && (
                      <div className="small">
                        <Link to={`/deployments/${result.deploymentId}`}>zur Verteilung</Link>
                      </div>
                    )}
                    {result?.error && <div className="error-text small">{result.error}</div>}
                  </td>
                  <td className="actions">
                    {a.canDecide && (
                      <>
                        <input placeholder="Begründung" value={reason[a.id] ?? ''} onChange={(e) => setReason({ ...reason, [a.id]: e.target.value })} />
                        <button onClick={() => void decide(a.id, true)}>Freigeben</button>
                        <button className="link danger" disabled={!reason[a.id]} onClick={() => void decide(a.id, false)}>
                          Ablehnen
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
            {list.data?.items.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  Keine Einträge.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
