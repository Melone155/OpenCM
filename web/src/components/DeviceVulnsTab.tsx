import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, unwrap } from '../api/client';
import { fmtDate, useLoad } from '../hooks';
import { CONF_LABEL, confHint, KevBadge, pct, SeverityBadge } from '../pages/VulnerabilitiesPage';

export function DeviceVulnsTab({ deviceId }: { deviceId: string }) {
  const [status, setStatus] = useState<'open' | 'fixed' | 'all'>('open');
  const v = useLoad(() => unwrap(api.GET('/devices/{id}/vulnerabilities', { params: { path: { id: deviceId }, query: { status } } })), [deviceId, status]);
  return (
    <>
      <select value={status} onChange={(e) => setStatus(e.target.value as typeof status)}>
        <option value="open">offen</option>
        <option value="fixed">behoben</option>
        <option value="all">alle</option>
      </select>
      {v.error && <div className="error">{v.error}</div>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>CVE</th>
              <th>Schweregrad</th>
              <th>EPSS</th>
              <th>Software</th>
              <th>Zuordnung</th>
              <th>Erkannt</th>
              {status !== 'open' && <th>Behoben</th>}
            </tr>
          </thead>
          <tbody>
            {v.data?.items.map((x) => (
              <tr key={`${x.cveId}-${x.softwareName}`}>
                <td>
                  <Link to={`/vulnerabilities/${x.cveId}`}>{x.cveId}</Link> <KevBadge kev={x.kev} />
                  {x.acceptedAt && <span className="badge">akzeptiert</span>}
                </td>
                <td>
                  <SeverityBadge severity={x.cvssSeverity} score={x.cvssScore} />
                </td>
                <td>{pct(x.epss)}</td>
                <td>
                  {x.softwareName} <span className="muted">{x.softwareVersion}</span>
                </td>
                <td title={confHint(x.confidence, x.vendor)}>
                  {CONF_LABEL[x.confidence]}
                  {x.vendor === 'osv' && <span className="badge"> Distribution</span>}
                </td>
                <td>{fmtDate(x.firstSeen)}</td>
                {status !== 'open' && <td>{fmtDate(x.fixedAt)}</td>}
              </tr>
            ))}
            {v.data?.items.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">
                  Keine Befunde.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
