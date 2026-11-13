import { useState } from 'react';
import { api, unwrap } from '../api/client';
import { fmtDate, useLoad } from '../hooks';

const PAGE = 50;

function exportUrl(format: 'csv' | 'json', action: string) {
  const q = new URLSearchParams({ format });
  if (action) q.set('action', action);
  return `/api/v1/audit-log/export?${q.toString()}`;
}

export function AuditPage() {
  const [action, setAction] = useState('');
  const [offset, setOffset] = useState(0);
  const log = useLoad(
    () => unwrap(api.GET('/audit-log', { params: { query: { action: action || undefined, limit: PAGE, offset } } })),
    [action, offset],
  );

  return (
    <>
      <div className="toolbar">
        <h1>Audit-Log</h1>
        <input
          placeholder="Aktion, z. B. user.create"
          value={action}
          onChange={(e) => {
            setAction(e.target.value);
            setOffset(0);
          }}
        />
        <a className="button" href={exportUrl('csv', action)}>
          Export CSV
        </a>
        <a className="button" href={exportUrl('json', action)}>
          Export JSON
        </a>
      </div>
      {log.error && <div className="error">{log.error}</div>}
      <table>
        <thead>
          <tr>
            <th>Zeit</th>
            <th>Akteur</th>
            <th>Aktion</th>
            <th>Ziel</th>
            <th>Details</th>
            <th>IP</th>
          </tr>
        </thead>
        <tbody>
          {log.data?.items.map((e) => (
            <tr key={e.id}>
              <td>{fmtDate(e.at)}</td>
              <td>
                {e.actorName} <span className="muted">({e.actorType})</span>
              </td>
              <td>
                <code>{e.action}</code>
              </td>
              <td>{e.targetType ? `${e.targetType} ${e.targetId ?? ''}` : '–'}</td>
              <td className="perms">
                <code>{JSON.stringify(e.details)}</code>
              </td>
              <td>{e.ip ?? '–'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {log.data && (
        <div className="pager">
          <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
            Zurück
          </button>
          <span className="muted">
            {log.data.total === 0 ? 0 : offset + 1}–{Math.min(offset + PAGE, log.data.total)} von {log.data.total}
          </span>
          <button disabled={offset + PAGE >= log.data.total} onClick={() => setOffset(offset + PAGE)}>
            Weiter
          </button>
        </div>
      )}
    </>
  );
}
