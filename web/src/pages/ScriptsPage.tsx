import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api, unwrap } from '../api/client';
import { useAuth } from '../auth';
import { fmtDate, useLoad } from '../hooks';

export const STATUS_LABEL: Record<string, string> = { draft: 'Entwurf', approved: 'freigegeben', retired: 'zurückgezogen' };

export function ScriptsPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const scripts = useLoad(() => unwrap(api.GET('/scripts', { params: { query: { search: search || undefined } } })), [search]);
  const interpreters = useLoad(() => unwrap(api.GET('/interpreters')));
  const [form, setForm] = useState<{ name: string; interpreter: string; description: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showTemplates, setShowTemplates] = useState(false);
  const templates = useLoad(() => (showTemplates ? unwrap(api.GET('/script-templates')) : Promise.resolve({ items: [] })), [showTemplates]);
  const label =(i: string) => interpreters.data?.items.find((x) => x.name === i)?.label ?? i;

  async function create(e: FormEvent) {
    e.preventDefault();
    if (!form) return;
    try {
      const s = await unwrap(
        api.POST('/scripts', {
          body: {
            ...form,
            interpreter: form.interpreter as 'bash',
            content: form.interpreter === 'powershell' ? 'Write-Output "Hallo von $env:COMPUTERNAME"\n' : form.interpreter === 'python' ? 'print("Hallo")\n' : form.interpreter === 'cmd' ? '@echo Hallo von %COMPUTERNAME%\r\n' : 'echo "Hallo von $(hostname)"\n',
          },
        }),
      );
      navigate(`/scripts/${s.id}`);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <>
      <div className="toolbar">
        <h1>Skripte</h1>
        <input placeholder="Suchen …" value={search} onChange={(e) => setSearch(e.target.value)} />
        {can('scripts:create') && <button onClick={() => setForm({ name: '', interpreter: 'powershell', description: '' })}>Neues Skript</button>}
        {can('scripts:create') && (
          <button className="link" onClick={() => setShowTemplates(!showTemplates)}>
            Aus Vorlage …
          </button>
        )}
      </div>
      {error && <div className="error">{error}</div>}
      {showTemplates && (
        <div className="card">
          <h2>Vorlagen</h2>
          <p className="muted">Eine Vorlage wird als normales Skript übernommen und ist sofort einsetzbar (wer Skripte nicht freigeben darf, erhält einen Entwurf).</p>
          <ul className="plain">
            {templates.data?.items.map((t) => (
              <li key={t.id}>
                <button
                  className="link"
                  onClick={() =>
                    void unwrap(api.POST('/scripts', { body: { name: t.name, description: t.description, interpreter: t.interpreter, content: t.content, parameters: t.parameters, changeNote: `Vorlage ${t.id}` } }))
                      .then((s) => navigate(`/scripts/${s.id}`))
                      .catch((e: Error) => setError(e.message))
                  }
                >
                  {t.name}
                </button>{' '}
                <span className="muted small">{t.description}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {form && (
        <form className="card form-inline" onSubmit={create}>
          <input placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required autoFocus />
          <select value={form.interpreter} onChange={(e) => setForm({ ...form, interpreter: e.target.value })}>
            {interpreters.data?.items.map((i) => (
              <option key={i.name} value={i.name}>
                {i.label} ({i.os.join(', ')})
              </option>
            ))}
          </select>
          <input placeholder="Beschreibung" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          <button type="submit">Anlegen</button>
          <button type="button" className="link" onClick={() => setForm(null)}>
            Abbrechen
          </button>
        </form>
      )}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Interpreter</th>
              <th>Version</th>
              <th>Freigegeben</th>
              <th>Geändert</th>
            </tr>
          </thead>
          <tbody>
            {scripts.data?.items.map((s) => (
              <tr key={s.id}>
                <td>
                  <Link to={`/scripts/${s.id}`}>{s.name}</Link>
                  {s.description && <div className="muted">{s.description}</div>}
                </td>
                <td>{label(s.interpreter)}</td>
                <td>v{s.latestVersion}</td>
                <td>{s.approvedVersion ? <span className="badge ok">v{s.approvedVersion}</span> : <span className="badge">keine</span>}</td>
                <td>{fmtDate(s.updatedAt)}</td>
              </tr>
            ))}
            {scripts.data?.items.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  Noch keine Skripte.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
