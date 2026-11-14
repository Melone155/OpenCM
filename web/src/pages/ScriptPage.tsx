import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, unwrap, type Schemas } from '../api/client';
import { useAuth } from '../auth';
import { CodeEditor } from '../components/CodeEditor';
import { DevicePicker, ParamsEditor, ParamsForm, type ParamValues } from '../components/forms';
import { TaskOutput } from '../components/TaskOutput';
import { fmtDate, useLoad } from '../hooks';
import { STATUS_LABEL } from './ScriptsPage';
import { DeleteButton } from './UsersPage';

type Param = Schemas['ScriptParameter'];

export function ScriptPage() {
  const { id = '' } = useParams();
  const { can } = useAuth();
  const navigate = useNavigate();
  const script = useLoad(() => unwrap(api.GET('/scripts/{id}', { params: { path: { id } } })), [id]);
  const interpreters = useLoad(() => unwrap(api.GET('/interpreters')));
  const [selected, setSelected] = useState<number | null>(null);
  const version = useLoad(
    () => (selected ? unwrap(api.GET('/scripts/{id}/versions/{version}', { params: { path: { id, version: selected } } })) : Promise.resolve(null)),
    [id, selected],
  );
  const [draft, setDraft] = useState<{ content: string; parameters: Param[]; changeNote: string } | null>(null);
  const [testDevices, setTestDevices] = useState<string[]>([]);
  const [testParams, setTestParams] = useState<ParamValues>({});
  const [testTask, setTestTask] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    if (script.data && selected === null) setSelected(script.data.latestVersion);
  }, [script.data, selected]);

  const s = script.data;
  const v = version.data;
  if (script.error) return <div className="error">{script.error}</div>;
  if (!s) return <div className="muted">Lade …</div>;
  const interp = interpreters.data?.items.find((i) => i.name === s.interpreter);

  async function act<T>(p: Promise<T>, done: string) {
    setError(null);
    setMsg(null);
    try {
      const r = await p;
      setMsg(done);
      await script.reload();
      await version.reload();
      return r;
    } catch (e) {
      setError((e as Error).message);
      return null;
    }
  }

  async function saveVersion() {
    if (!draft) return;
    const r = await act(unwrap(api.POST('/scripts/{id}/versions', { params: { path: { id } }, body: draft })), can('scripts:approve') ? 'Neue Version gespeichert und freigegeben.' : 'Neue Version als Entwurf gespeichert.');
    if (r) {
      setDraft(null);
      setSelected(r.version);
    }
  }

  async function runTest() {
    if (!v || testDevices.length !== 1) return;
    const run = await act(
      unwrap(api.POST('/scripts/{id}/versions/{version}/test', { params: { path: { id, version: v.version } }, body: { deviceId: testDevices[0]!, params: testParams } })),
      'Testlauf gestartet.',
    );
    if (run) {
      const t = await unwrap(api.GET('/runs/{id}/tasks', { params: { path: { id: run.id } } }));
      setTestTask(t.items[0]?.id ?? null);
    }
  }

  const editing = draft !== null;
  return (
    <>
      <div className="toolbar">
        <h1>
          <Link to="/scripts" className="muted">
            Skripte
          </Link>{' '}
          / {s.name}
        </h1>
        <span className="badge">{interp?.label ?? s.interpreter}</span>
        {can('scripts:delete') && <DeleteButton onConfirm={() => act(unwrap(api.DELETE('/scripts/{id}', { params: { path: { id } } })), '').then((r) => r !== null && navigate('/scripts'))} />}
      </div>
      {s.description && <p className="muted">{s.description}</p>}
      {error && <div className="error">{error}</div>}
      {msg && <div className="card">{msg}</div>}

      <div className="grid-side">
        <div>
          {editing ? (
            <div className="card">
              <h2>Neue Version v{s.latestVersion + 1}</h2>
              <CodeEditor value={draft.content} onChange={(content) => setDraft({ ...draft, content })} interpreter={s.interpreter} />
              <h2>Parameter</h2>
              <ParamsEditor defs={draft.parameters} onChange={(parameters) => setDraft({ ...draft, parameters })} />
              <label>
                Änderungsnotiz
                <input value={draft.changeNote} onChange={(e) => setDraft({ ...draft, changeNote: e.target.value })} />
              </label>
              <p>
                <button onClick={() => void saveVersion()}>{can('scripts:approve') ? 'Speichern' : 'Als Entwurf speichern'}</button>{' '}
                <button className="link" onClick={() => setDraft(null)}>
                  Verwerfen
                </button>
              </p>
            </div>
          ) : v ? (
            <div className="card">
              <div className="toolbar">
                <h2>
                  Version {v.version} <span className={v.status === 'approved' ? 'badge ok' : v.status === 'retired' ? 'badge danger' : 'badge'}>{STATUS_LABEL[v.status]}</span>
                </h2>
                {can('scripts:update') && (
                  <button onClick={() => setDraft({ content: v.content, parameters: v.parameters, changeNote: '' })}>Bearbeiten (neue Version)</button>
                )}
                {can('scripts:approve') && v.status === 'draft' && (
                  <button onClick={() => void act(unwrap(api.POST('/scripts/{id}/versions/{version}/approve', { params: { path: { id, version: v.version } } })), `Version ${v.version} freigegeben.`)}>
                    Freigeben
                  </button>
                )}
                {can('scripts:approve') && v.status !== 'retired' && (
                  <button className="link danger" onClick={() => void act(unwrap(api.POST('/scripts/{id}/versions/{version}/retire', { params: { path: { id, version: v.version } } })), `Version ${v.version} zurückgezogen.`)}>
                    Zurückziehen
                  </button>
                )}
              </div>
              <CodeEditor value={v.content} interpreter={s.interpreter} readOnly />
              <p className="muted">
                SHA-256 <code>{v.sha256}</code>
                {v.changeNote && <> · {v.changeNote}</>}
              </p>
              {v.parameters.length > 0 && (
                <p className="muted">Parameter: {v.parameters.map((p) => `${p.name} (${p.type}${p.required ? ', Pflicht' : ''})`).join(', ')}</p>
              )}
            </div>
          ) : (
            <div className="muted">Lade Version …</div>
          )}

          {!editing && v && can('scripts:execute') && v.status !== 'retired' && (
            <div className="card">
              <h2>Testlauf auf einem Gerät</h2>
              <p className="muted">Die Ausgabe erscheint live. Entwürfe kann nur testen, wer Skripte auch freigeben darf.</p>
              <DevicePicker selected={testDevices} onChange={(ids) => setTestDevices(ids.slice(-1))} os={interp?.os} />
              <ParamsForm defs={v.parameters} values={testParams} onChange={setTestParams} />
              <button disabled={testDevices.length !== 1} onClick={() => void runTest()}>
                Testlauf starten
              </button>
              {testTask && (
                <>
                  <h2>Ausgabe</h2>
                  <TaskOutput taskId={testTask} />
                </>
              )}
            </div>
          )}
        </div>

        <aside className="card">
          <h2>Versionen</h2>
          <ul className="plain versions">
            {s.versions.map((x) => (
              <li key={x.id}>
                <button className={x.version === selected && !editing ? 'link active' : 'link'} onClick={() => { setDraft(null); setSelected(x.version); setTestTask(null); }}>
                  v{x.version}
                </button>{' '}
                <span className={x.status === 'approved' ? 'badge ok' : x.status === 'retired' ? 'badge danger' : 'badge'}>{STATUS_LABEL[x.status]}</span>
                <div className="muted small">
                  {fmtDate(x.createdAt)}
                  {x.changeNote && ` – ${x.changeNote}`}
                </div>
              </li>
            ))}
          </ul>
        </aside>
      </div>
    </>
  );
}
