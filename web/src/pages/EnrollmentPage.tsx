import { useState, type FormEvent } from 'react';
import { api, unwrap } from '../api/client';
import { fmtBytes } from '../format';
import { fmtDate, useLoad } from '../hooks';

type Created = { token: string; name: string; installCommands: { windows: string; linux: string; macos: string } };

export function EnrollmentPage() {
  const tokens = useLoad(() => unwrap(api.GET('/enrollment-tokens')));
  const downloads = useLoad(() => unwrap(api.GET('/agent-downloads')));
  const [name, setName] = useState('');
  const [hours, setHours] = useState(168);
  const [maxUses, setMaxUses] = useState('');
  const [created, setCreated] = useState<Created | null>(null);
  const [osTab, setOsTab] = useState<'windows' | 'linux' | 'macos'>('windows');
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function create(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const res = await unwrap(
        api.POST('/enrollment-tokens', { body: { name, expiresInHours: hours || null, maxUses: maxUses ? Number(maxUses) : null } }),
      );
      setCreated(res);
      setName('');
      await tokens.reload();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  async function remove(id: string, label: string) {
    if (!window.confirm(`Token „${label}“ löschen? Er funktioniert danach nicht mehr. Bereits registrierte Geräte bleiben erhalten.`)) return;
    setError(null);
    try {
      await unwrap(api.DELETE('/enrollment-tokens/{id}', { params: { path: { id } } }));
      await tokens.reload();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const now = Date.now();
  return (
    <>
      <h1>Geräte hinzufügen</h1>

      <form className="card form-inline" onSubmit={create}>
        <input placeholder="Bezeichnung, z. B. „Rollout Buchhaltung“" value={name} onChange={(e) => setName(e.target.value)} required />
        <label className="inline">
          gültig
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            <option value={24}>1 Tag</option>
            <option value={168}>7 Tage</option>
            <option value={720}>30 Tage</option>
            <option value={8760}>1 Jahr</option>
            <option value={0}>unbegrenzt</option>
          </select>
        </label>
        <input type="number" min={1} placeholder="max. Geräte (leer = unbegrenzt)" value={maxUses} onChange={(e) => setMaxUses(e.target.value)} />
        <button type="submit">Token erstellen</button>
      </form>
      {error && <div className="error">{error}</div>}

      {created && (
        <div className="card highlight">
          <h2>Token „{created.name}“ erstellt</h2>
          <p>
            Dieser Token wird <strong>nur jetzt</strong> angezeigt. Befehl auf dem Zielgerät als Administrator bzw. root ausführen:
          </p>
          <div className="tabs">
            {(['windows', 'linux', 'macos'] as const).map((o) => (
              <button key={o} className={osTab === o ? 'tab active' : 'tab'} onClick={() => setOsTab(o)}>
                {o === 'windows' ? 'Windows (PowerShell)' : o === 'linux' ? 'Linux' : 'macOS'}
              </button>
            ))}
          </div>
          <pre className="code">{created.installCommands[osTab]}</pre>
          <button onClick={() => void copy(created.installCommands[osTab])}>{copied ? 'Kopiert ✓' : 'Kopieren'}</button>{' '}
          <button className="link" onClick={() => setCreated(null)}>
            Schließen
          </button>
        </div>
      )}

      <h2>Enrollment-Tokens</h2>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Bezeichnung</th>
              <th>Nutzung</th>
              <th>Gültig bis</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {tokens.data?.items.map((t) => {
              const expired = t.expiresAt != null && new Date(t.expiresAt).getTime() < now;
              const usedUp = t.maxUses !== null && t.maxUses !== undefined && t.uses >= t.maxUses;
              return (
                <tr key={t.id}>
                  <td>{t.name}</td>
                  <td>
                    {t.uses}
                    {t.maxUses ? ` / ${t.maxUses}` : ''}
                  </td>
                  <td>{t.expiresAt ? fmtDate(t.expiresAt) : <span className="muted">läuft nicht ab</span>}</td>
                  <td>
                    {t.revokedAt ? (
                      <span className="badge">widerrufen</span>
                    ) : expired ? (
                      <span className="badge">abgelaufen</span>
                    ) : usedUp ? (
                      <span className="badge">aufgebraucht</span>
                    ) : (
                      <span className="badge ok">aktiv</span>
                    )}
                  </td>
                  <td className="actions">
                    <button className="link danger" onClick={() => void remove(t.id, t.name)}>
                      Löschen
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <h2>Agent-Downloads {downloads.data?.version && <span className="muted">Version {downloads.data.version}</span>}</h2>
      {downloads.data && downloads.data.items.length === 0 ? (
        <p className="muted">
          Auf dem Server liegen keine Agent-Binaries. Die offiziellen Server-Images enthalten sie; bei einem eigenen Build ohne Agent die
          CI-Artefakte <code>opencm-agent-&lt;os&gt;-&lt;arch&gt;</code> in das Volume <code>files</code> unter <code>agent/</code> kopieren (siehe
          docs/operations.md).
        </p>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>System</th>
                <th>Größe</th>
                <th>SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {downloads.data?.items.map((b) => (
                <tr key={`${b.os}-${b.arch}`}>
                  <td>
                    <a href={b.url}>
                      {b.os} / {b.arch}
                    </a>
                  </td>
                  <td>{fmtBytes(b.sizeBytes)}</td>
                  <td className="perms">
                    <code>{b.sha256}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
