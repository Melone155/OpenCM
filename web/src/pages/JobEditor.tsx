import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api, unwrap, type Schemas } from '../api/client';
import { DevicePicker, ParamsForm, type ParamValues } from '../components/forms';
import { useLoad } from '../hooks';

type JobInput = Schemas['JobInput'];
interface StepState {
  scriptId: string;
  version?: number;
  params: ParamValues;
  continueOnError: boolean;
  customFieldId: string | null;
}

const DAYS = ['So', 'Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa'];

function toLocalInput(iso: string | null | undefined): string {
  if (!iso) return '';
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function JobEditor() {
  const { id } = useParams();
  const navigate = useNavigate();
  const scripts = useLoad(() => unwrap(api.GET('/scripts')));
  const groups = useLoad(() => unwrap(api.GET('/device-groups')));
  const fields = useLoad(() => unwrap(api.GET('/custom-fields')));
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(!id);
  const [job, setJob] = useState({
    name: '',
    description: '',
    enabled: true,
    trigger: 'manual' as JobInput['trigger'],
    runAt: '',
    cron: '0 3 * * *',
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
  });
  const [targets, setTargets] = useState({ deviceIds: [] as string[], groupIds: [] as string[], allDevices: false });
  const [steps, setSteps] = useState<StepState[]>([]);
  const [opts, setOpts] = useState({ timeoutSeconds: 3600, maxRetries: 0, retryDelaySeconds: 300, stopOnError: true });
  const [win, setWin] = useState<{ days: number[]; start: string; end: string } | null>(null);
  const [paramDefs, setParamDefs] = useState<Record<string, Schemas['ScriptParameter'][]>>({});

  useEffect(() => {
    if (!id) return;
    void unwrap(api.GET('/jobs/{id}', { params: { path: { id } } })).then((j) => {
      setJob({
        name: j.name,
        description: j.description,
        enabled: j.enabled,
        trigger: j.trigger,
        runAt: toLocalInput(j.runAt),
        cron: j.cron ?? '0 3 * * *',
        timezone: j.timezone,
      });
      setTargets({ deviceIds: j.targets.deviceIds ?? [], groupIds: j.targets.groupIds ?? [], allDevices: !!j.targets.allDevices });
      setSteps(j.steps.map((s) => ({ scriptId: s.scriptId, version: s.version, params: s.params as ParamValues, continueOnError: s.continueOnError, customFieldId: s.customFieldId ?? null })));
      setOpts({
        timeoutSeconds: j.options.timeoutSeconds ?? 3600,
        maxRetries: j.options.maxRetries ?? 0,
        retryDelaySeconds: j.options.retryDelaySeconds ?? 300,
        stopOnError: j.options.stopOnError ?? true,
      });
      setWin((j.options.maintenanceWindow as typeof win) ?? null);
      setLoaded(true);
    });
  }, [id]);

  // load parameter definitions of the selected (or newest approved) version
  useEffect(() => {
    for (const s of steps) {
      const script = scripts.data?.items.find((x) => x.id === s.scriptId);
      const version = s.version ?? script?.approvedVersion;
      const key = `${s.scriptId}:${version}`;
      if (!version || paramDefs[key]) continue;
      void unwrap(api.GET('/scripts/{id}/versions/{version}', { params: { path: { id: s.scriptId, version } } })).then((v) =>
        setParamDefs((p) => ({ ...p, [key]: v.parameters })),
      );
    }
  }, [steps, scripts.data, paramDefs]);

  const approved = (scripts.data?.items ?? []).filter((s) => s.approvedVersion);
  const updateStep = (i: number, patch: Partial<StepState>) => setSteps(steps.map((s, j) => (i === j ? { ...s, ...patch } : s)));
  const move = (i: number, d: number) => {
    const next = [...steps];
    const [s] = next.splice(i, 1);
    next.splice(i + d, 0, s!);
    setSteps(next);
  };

  async function save() {
    setError(null);
    const body: JobInput = {
      ...job,
      runAt: job.trigger === 'once' && job.runAt ? new Date(job.runAt).toISOString() : null,
      cron: job.trigger === 'cron' ? job.cron : null,
      targets,
      options: { ...opts, maintenanceWindow: win },
      steps: steps.map((s) => ({ scriptId: s.scriptId, version: s.version, params: s.params, continueOnError: s.continueOnError, customFieldId: s.customFieldId })),
    };
    try {
      const saved = id
        ? await unwrap(api.PATCH('/jobs/{id}', { params: { path: { id } }, body }))
        : await unwrap(api.POST('/jobs', { body }));
      navigate(`/jobs/${saved.id}`);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  if (!loaded) return <div className="muted">Lade …</div>;
  return (
    <>
      <h1>{id ? 'Job bearbeiten' : 'Neuer Job'}</h1>
      {error && <div className="error">{error}</div>}

      <div className="card form-grid">
        <label>
          Name
          <input value={job.name} onChange={(e) => setJob({ ...job, name: e.target.value })} required />
        </label>
        <label>
          Beschreibung
          <input value={job.description} onChange={(e) => setJob({ ...job, description: e.target.value })} />
        </label>
        <label>
          Auslöser
          <select value={job.trigger} onChange={(e) => setJob({ ...job, trigger: e.target.value as JobInput['trigger'] })}>
            <option value="manual">manuell (Jetzt ausführen)</option>
            <option value="once">einmalig zu einem Zeitpunkt</option>
            <option value="cron">wiederkehrend (Cron)</option>
            <option value="agent_start">bei Agent-Start</option>
            <option value="user_login">bei Benutzer-Login</option>
          </select>
        </label>
        {job.trigger === 'once' && (
          <label>
            Zeitpunkt
            <input type="datetime-local" value={job.runAt} onChange={(e) => setJob({ ...job, runAt: e.target.value })} />
          </label>
        )}
        {job.trigger === 'cron' && (
          <>
            <label>
              Cron (Minute Stunde Tag Monat Wochentag)
              <input value={job.cron} onChange={(e) => setJob({ ...job, cron: e.target.value })} placeholder="0 3 * * 1-5" />
            </label>
            <label>
              Zeitzone
              <input value={job.timezone} onChange={(e) => setJob({ ...job, timezone: e.target.value })} />
            </label>
          </>
        )}
        <label className="check">
          <input type="checkbox" checked={job.enabled} onChange={(e) => setJob({ ...job, enabled: e.target.checked })} />
          aktiv
        </label>
      </div>

      <h2>Ziele</h2>
      <div className="card">
        <label className="check">
          <input type="checkbox" checked={targets.allDevices} onChange={(e) => setTargets({ ...targets, allDevices: e.target.checked })} />
          <strong>Alle Geräte</strong>
        </label>
        {!targets.allDevices && (
          <div className="grid2">
            <div>
              <h3>Gerätegruppen</h3>
              {groups.data?.items.map((g) => (
                <label key={g.id} className="check">
                  <input
                    type="checkbox"
                    checked={targets.groupIds.includes(g.id)}
                    onChange={(e) => setTargets({ ...targets, groupIds: e.target.checked ? [...targets.groupIds, g.id] : targets.groupIds.filter((x) => x !== g.id) })}
                  />
                  {g.name} <span className="muted">({g.kind === 'dynamic' ? 'dynamisch' : 'statisch'}, {g.memberCount})</span>
                </label>
              ))}
              {groups.data?.items.length === 0 && <p className="muted">Keine Gruppen angelegt.</p>}
            </div>
            <div>
              <h3>Einzelne Geräte</h3>
              <DevicePicker selected={targets.deviceIds} onChange={(deviceIds) => setTargets({ ...targets, deviceIds })} />
            </div>
          </div>
        )}
      </div>

      <h2>Schritte</h2>
      {steps.map((s, i) => {
        const script = scripts.data?.items.find((x) => x.id === s.scriptId);
        const defs = paramDefs[`${s.scriptId}:${s.version ?? script?.approvedVersion}`] ?? [];
        return (
          <div key={i} className="card">
            <div className="toolbar">
              <h3>
                {i + 1}. {script?.name ?? 'Skript'}
              </h3>
              <button className="link" disabled={i === 0} onClick={() => move(i, -1)}>
                ↑
              </button>
              <button className="link" disabled={i === steps.length - 1} onClick={() => move(i, 1)}>
                ↓
              </button>
              <button className="link danger" onClick={() => setSteps(steps.filter((_, j) => j !== i))}>
                Entfernen
              </button>
            </div>
            <div className="form-grid">
              <label>
                Version
                <select value={s.version ?? ''} onChange={(e) => updateStep(i, { version: e.target.value ? Number(e.target.value) : undefined })}>
                  <option value="">neueste freigegebene (v{script?.approvedVersion})</option>
                  {script?.approvedVersion && <option value={script.approvedVersion}>fest: v{script.approvedVersion}</option>}
                  {s.version && s.version !== script?.approvedVersion && <option value={s.version}>fest: v{s.version}</option>}
                </select>
              </label>
              <label>
                Ausgabe in Feld speichern
                <select value={s.customFieldId ?? ''} onChange={(e) => updateStep(i, { customFieldId: e.target.value || null })}>
                  <option value="">–</option>
                  {fields.data?.items.map((f) => (
                    <option key={f.id} value={f.id}>
                      {f.label} ({f.type})
                    </option>
                  ))}
                </select>
              </label>
              <label className="check">
                <input type="checkbox" checked={s.continueOnError} onChange={(e) => updateStep(i, { continueOnError: e.target.checked })} />
                Fehler ignorieren
              </label>
            </div>
            <ParamsForm defs={defs} values={s.params} onChange={(params) => updateStep(i, { params })} />
          </div>
        );
      })}
      <div className="card form-inline">
        <select
          value=""
          onChange={(e) => e.target.value && setSteps([...steps, { scriptId: e.target.value, params: {}, continueOnError: false, customFieldId: null }])}
        >
          <option value="">+ Schritt hinzufügen (freigegebenes Skript wählen) …</option>
          {approved.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name} ({s.interpreter}, v{s.approvedVersion})
            </option>
          ))}
        </select>
      </div>

      <h2>Optionen</h2>
      <div className="card form-grid">
        <label>
          Timeout (Sekunden)
          <input type="number" min={10} value={opts.timeoutSeconds} onChange={(e) => setOpts({ ...opts, timeoutSeconds: Number(e.target.value) })} />
        </label>
        <label>
          Wiederholungen bei Fehler
          <input type="number" min={0} max={10} value={opts.maxRetries} onChange={(e) => setOpts({ ...opts, maxRetries: Number(e.target.value) })} />
        </label>
        <label>
          Pause vor Wiederholung (s)
          <input type="number" min={0} value={opts.retryDelaySeconds} onChange={(e) => setOpts({ ...opts, retryDelaySeconds: Number(e.target.value) })} />
        </label>
        <label className="check">
          <input type="checkbox" checked={opts.stopOnError} onChange={(e) => setOpts({ ...opts, stopOnError: e.target.checked })} />
          nach fehlgeschlagenem Schritt abbrechen
        </label>
        <fieldset>
          <legend>
            <label className="check">
              <input type="checkbox" checked={!!win} onChange={(e) => setWin(e.target.checked ? { days: [1, 2, 3, 4, 5], start: '22:00', end: '05:00' } : null)} />
              Wartungsfenster
            </label>
          </legend>
          {win && (
            <div className="form-inline">
              {DAYS.map((d, i) => (
                <label key={d} className="check">
                  <input
                    type="checkbox"
                    checked={win.days.includes(i)}
                    onChange={(e) => setWin({ ...win, days: e.target.checked ? [...win.days, i].sort() : win.days.filter((x) => x !== i) })}
                  />
                  {d}
                </label>
              ))}
              <input type="time" value={win.start} onChange={(e) => setWin({ ...win, start: e.target.value })} />
              bis
              <input type="time" value={win.end} onChange={(e) => setWin({ ...win, end: e.target.value })} />
              <span className="muted">(Zeitzone {job.timezone})</span>
            </div>
          )}
        </fieldset>
      </div>

      <p>
        <button onClick={() => void save()} disabled={!job.name || steps.length === 0}>
          Speichern
        </button>{' '}
        <button className="link" onClick={() => navigate(id ? `/jobs/${id}` : '/jobs')}>
          Abbrechen
        </button>
      </p>
    </>
  );
}
