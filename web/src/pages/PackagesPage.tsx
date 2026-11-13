import { useEffect, useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, unwrap, type Schemas } from '../api/client';
import { useAuth } from '../auth';
import { DEFAULT_RINGS, hasTargets, RingsEditor, type Ring } from '../components/Rings';
import { fmtDate, useLoad } from '../hooks';
import { startDeployment } from './DeploymentsPage';
import { STATUS_LABEL } from './ScriptsPage';
import { DeleteButton } from './UsersPage';

type PackageType = Schemas['PackageType'];
type Platform = Schemas['Platform'];
type Rule = Schemas['DetectionRule'];
type Version = Schemas['PackageVersion'];

export const PLATFORM_LABEL: Record<Platform, string> = { windows: 'Windows', linux: 'Linux', macos: 'macOS' };

/** Mirror of the server's PACKAGE_TYPES (labels and what each type needs). */
export const TYPES: Record<PackageType, { label: string; platform: Platform | null; file: 'required' | 'optional' | 'none'; ref: string | null; args: string | null }> = {
  msi: { label: 'MSI-Paket', platform: 'windows', file: 'required', ref: null, args: 'zusätzliche msiexec-Eigenschaften, z. B. ALLUSERS=1 INSTALLDIR="C:\\Tools"' },
  exe: { label: 'EXE-Installer', platform: 'windows', file: 'required', ref: null, args: 'Silent-Parameter, z. B. /S oder /quiet /norestart' },
  winget: { label: 'winget', platform: 'windows', file: 'none', ref: 'winget-ID, z. B. Mozilla.Firefox', args: 'zusätzliche Argumente, z. B. --version 128.0' },
  choco: { label: 'Chocolatey', platform: 'windows', file: 'none', ref: 'Paketname, z. B. 7zip', args: 'zusätzliche Argumente, z. B. --version 23.1.0' },
  deb: { label: 'DEB-Datei', platform: 'linux', file: 'required', ref: 'Paketname (für Deinstallation)', args: 'zusätzliche apt-get-Argumente' },
  rpm: { label: 'RPM-Datei', platform: 'linux', file: 'required', ref: 'Paketname (für Deinstallation)', args: 'zusätzliche dnf-Argumente' },
  apt: { label: 'apt-Paket', platform: 'linux', file: 'none', ref: 'Paketname, z. B. htop', args: 'zusätzliche apt-get-Argumente' },
  dnf: { label: 'dnf-Paket', platform: 'linux', file: 'none', ref: 'Paketname, z. B. htop', args: 'zusätzliche dnf-Argumente' },
  pkg: { label: 'macOS-PKG', platform: 'macos', file: 'required', ref: null, args: 'zusätzliche installer-Argumente' },
  brew: { label: 'Homebrew', platform: 'macos', file: 'none', ref: 'Formel, z. B. jq', args: 'zusätzliche brew-Argumente' },
  script: { label: 'Eigene Befehle', platform: null, file: 'optional', ref: null, args: null },
};

const fmtSize = (n: number) => (n > 1024 ** 3 ? `${(n / 1024 ** 3).toFixed(1)} GB` : n > 1024 ** 2 ? `${(n / 1024 ** 2).toFixed(1)} MB` : `${Math.ceil(n / 1024)} KB`);

export function PackagesPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [platform, setPlatform] = useState<Platform | ''>('');
  const list = useLoad(() => unwrap(api.GET('/packages', { params: { query: { search: search || undefined, platform: platform || undefined } } })), [search, platform]);
  const [form, setForm] = useState<{ name: string; publisher: string; platform: Platform } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function create(e: FormEvent) {
    e.preventDefault();
    if (!form) return;
    try {
      const p = await unwrap(api.POST('/packages', { body: form }));
      navigate(`/packages/${p.id}`);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <>
      <div className="toolbar">
        <h1>Softwarepakete</h1>
        <input placeholder="Suchen …" value={search} onChange={(e) => setSearch(e.target.value)} />
        <select value={platform} onChange={(e) => setPlatform(e.target.value as Platform | '')}>
          <option value="">alle Plattformen</option>
          {Object.entries(PLATFORM_LABEL).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
        {can('software:create') && <button onClick={() => setForm({ name: '', publisher: '', platform: 'windows' })}>Neues Paket</button>}
      </div>
      {error && <div className="error">{error}</div>}
      {form && (
        <form className="card form-inline" onSubmit={create}>
          <input placeholder="Name, z. B. 7-Zip" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required autoFocus />
          <input placeholder="Hersteller" value={form.publisher} onChange={(e) => setForm({ ...form, publisher: e.target.value })} />
          <select value={form.platform} onChange={(e) => setForm({ ...form, platform: e.target.value as Platform })}>
            {Object.entries(PLATFORM_LABEL).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
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
              <th>Plattform</th>
              <th>Typ</th>
              <th>Neueste Version</th>
              <th>Freigegeben</th>
              <th>Geändert</th>
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((p) => (
              <tr key={p.id}>
                <td>
                  <Link to={`/packages/${p.id}`}>{p.name}</Link>
                  {p.publisher && <div className="muted small">{p.publisher}</div>}
                </td>
                <td>{PLATFORM_LABEL[p.platform]}</td>
                <td>{p.type ? TYPES[p.type].label : '–'}</td>
                <td>{p.latestVersion ?? '–'}</td>
                <td>{p.approvedVersion ? <span className="badge ok">{p.approvedVersion}</span> : <span className="badge">keine</span>}</td>
                <td>{fmtDate(p.updatedAt)}</td>
              </tr>
            ))}
            {list.data?.items.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  Noch keine Pakete.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

// ---------------------------------------------------------------- package detail

type VersionForm = {
  version: string;
  type: PackageType;
  packageRef: string;
  installArgs: string;
  installCommand: string;
  uninstallCommand: string;
  productCode: string;
  detection: Rule[];
  successCodes: string;
  rebootCodes: string;
  timeoutSeconds: number;
  changeNote: string;
};

const codes = (s: string) =>
  s
    .split(/[\s,;]+/)
    .filter(Boolean)
    .map(Number)
    .filter((n) => Number.isInteger(n));

function toForm(v: Version | null, platform: Platform): VersionForm {
  const defType: PackageType = platform === 'windows' ? 'msi' : platform === 'linux' ? 'apt' : 'pkg';
  return {
    version: v ? '' : '1.0',
    type: v?.type ?? defType,
    packageRef: v?.packageRef ?? '',
    installArgs: v?.installArgs ?? '',
    installCommand: v?.installCommand ?? '',
    uninstallCommand: v?.uninstallCommand ?? '',
    productCode: v?.productCode ?? '',
    detection: v?.detection ?? [],
    successCodes: (v?.successCodes ?? [0]).join(', '),
    rebootCodes: (v?.rebootCodes ?? [3010, 1641]).join(', '),
    timeoutSeconds: v?.timeoutSeconds ?? 3600,
    changeNote: '',
  };
}

function formBody(f: VersionForm) {
  return {
    packageRef: f.packageRef.trim() || null,
    installArgs: f.installArgs,
    installCommand: f.installCommand,
    uninstallCommand: f.uninstallCommand,
    productCode: f.productCode.trim() || null,
    detection: f.detection,
    successCodes: codes(f.successCodes),
    rebootCodes: codes(f.rebootCodes),
    timeoutSeconds: f.timeoutSeconds,
    changeNote: f.changeNote,
  };
}

export function PackagePage() {
  const { id = '' } = useParams();
  const { can, canScoped } = useAuth();
  const navigate = useNavigate();
  const pkg = useLoad(() => unwrap(api.GET('/packages/{id}', { params: { path: { id } } })), [id]);
  const [selected, setSelected] = useState<string | null>(null);
  const [edit, setEdit] = useState<{ mode: 'new' | 'edit'; form: VersionForm } | null>(null);
  const [tab, setTab] = useState<'versions' | 'compliance'>('versions');
  const [deploy, setDeploy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    if (pkg.data && !selected && pkg.data.versions[0]) setSelected(pkg.data.versions[0].id);
  }, [pkg.data, selected]);

  const p = pkg.data;
  if (pkg.error) return <div className="error">{pkg.error}</div>;
  if (!p) return <div className="muted">Lade …</div>;
  const v = p.versions.find((x) => x.id === selected) ?? null;
  const approved = p.versions.find((x) => x.status === 'approved') ?? null;

  async function act<T>(fn: () => Promise<T>, done: string) {
    setError(null);
    setMsg(null);
    try {
      const r = await fn();
      setMsg(done);
      await pkg.reload();
      return r;
    } catch (e) {
      setError((e as Error).message);
      return null;
    }
  }

  async function save() {
    if (!edit) return;
    const body = formBody(edit.form);
    if (edit.mode === 'new') {
      const r = await act(() => unwrap(api.POST('/packages/{id}/versions', { params: { path: { id } }, body: { ...body, version: edit.form.version, type: edit.form.type } })), 'Version als Entwurf angelegt.');
      if (r) {
        setEdit(null);
        setSelected(r.id);
      }
    } else if (v) {
      const r = await act(() => unwrap(api.PATCH('/packages/{id}/versions/{versionId}', { params: { path: { id, versionId: v.id } }, body })), 'Gespeichert.');
      if (r) setEdit(null);
    }
  }

  async function upload(file: File) {
    if (!v) return;
    await act(async () => {
      const res = await fetch(`/api/v1/packages/${id}/versions/${v.id}/file?name=${encodeURIComponent(file.name)}`, {
        method: 'PUT',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/octet-stream' },
        body: file,
      });
      if (!res.ok) {
        const e = (await res.json().catch(() => null)) as { error?: { message?: string } } | null;
        throw new Error(e?.error?.message ?? `Upload fehlgeschlagen (HTTP ${res.status})`);
      }
      return res.json();
    }, `„${file.name}“ hochgeladen, SHA-256 berechnet.`);
  }

  return (
    <>
      <div className="toolbar">
        <h1>
          <Link to="/packages" className="muted">
            Software
          </Link>{' '}
          / {p.name}
        </h1>
        <span className="badge">{PLATFORM_LABEL[p.platform]}</span>
        {can('software:execute') && approved && <button onClick={() => setDeploy(!deploy)}>Verteilen …</button>}
        {can('software:delete') && <DeleteButton onConfirm={() => act(() => unwrap(api.DELETE('/packages/{id}', { params: { path: { id } } })), '').then((r) => r !== null && navigate('/packages'))} />}
      </div>
      {p.publisher && <p className="muted">{p.publisher}</p>}
      {msg && <div className="card">{msg}</div>}
      {error && <div className="error">{error}</div>}
      {deploy && approved && <DeployForm packageName={p.name} version={approved} platform={p.platform} onCancel={() => setDeploy(false)} />}

      <div className="tabs" role="tablist">
        <button role="tab" className={tab === 'versions' ? 'tab active' : 'tab'} onClick={() => setTab('versions')}>
          Versionen
        </button>
        {canScoped('software:read') && (
          <button role="tab" className={tab === 'compliance' ? 'tab active' : 'tab'} onClick={() => setTab('compliance')}>
            Installationsstand
          </button>
        )}
      </div>

      {tab === 'compliance' && <Compliance id={id} />}

      {tab === 'versions' && (
        <div className="grid-side">
          <div className="card">
            <h2>Versionen</h2>
            <ul className="plain">
              {p.versions.map((x) => (
                <li key={x.id}>
                  <button className={x.id === selected ? 'link active' : 'link'} onClick={() => { setSelected(x.id); setEdit(null); }}>
                    {x.version}
                  </button>{' '}
                  <span className={x.status === 'approved' ? 'badge ok' : 'badge'}>{STATUS_LABEL[x.status]}</span>
                </li>
              ))}
            </ul>
            {can('software:create') && (
              <button className="link" onClick={() => setEdit({ mode: 'new', form: toForm(v, p.platform) })}>
                + Neue Version
              </button>
            )}
          </div>
          <div>
            {edit ? (
              <VersionEditor platform={p.platform} mode={edit.mode} value={edit.form} onChange={(form) => setEdit({ ...edit, form })} onSave={() => void save()} onCancel={() => setEdit(null)} />
            ) : v ? (
              <VersionView
                v={v}
                platform={p.platform}
                packageId={id}
                onEdit={can('software:update') && v.status === 'draft' ? () => setEdit({ mode: 'edit', form: { ...toForm(v, p.platform), version: v.version } }) : undefined}
                onUpload={can('software:update') && v.status === 'draft' && TYPES[v.type].file !== 'none' ? (f) => void upload(f) : undefined}
                onApprove={can('software:approve') && v.status === 'draft' ? () => void act(() => unwrap(api.POST('/packages/{id}/versions/{versionId}/approve', { params: { path: { id, versionId: v.id } } })), 'Version freigegeben.') : undefined}
                onRetire={can('software:approve') && v.status === 'approved' ? () => void act(() => unwrap(api.POST('/packages/{id}/versions/{versionId}/retire', { params: { path: { id, versionId: v.id } } })), 'Version zurückgezogen.') : undefined}
                onDelete={
                  can('software:delete') && v.status === 'draft'
                    ? () => act(() => unwrap(api.DELETE('/packages/{id}/versions/{versionId}', { params: { path: { id, versionId: v.id } } })), 'Entwurf gelöscht.').then(() => setSelected(null))
                    : undefined
                }
              />
            ) : (
              <p className="muted">Noch keine Version – „+ Neue Version“ anlegen.</p>
            )}
          </div>
        </div>
      )}
    </>
  );
}

function VersionView({
  v,
  platform,
  packageId,
  onEdit,
  onUpload,
  onApprove,
  onRetire,
  onDelete,
}: {
  v: Version;
  platform: Platform;
  packageId: string;
  onEdit?: () => void;
  onUpload?: (f: File) => void;
  onApprove?: () => void;
  onRetire?: () => void;
  onDelete?: () => Promise<unknown>;
}) {
  const t = TYPES[v.type];
  const [preview, setPreview] = useState<'install' | 'uninstall' | null>(null);
  const script = useLoad(
    () => (preview ? unwrap(api.GET('/packages/{id}/versions/{versionId}/script', { params: { path: { id: packageId, versionId: v.id }, query: { action: preview } } })) : Promise.resolve(null)),
    [preview, v.id, v.updatedAt],
  );
  return (
    <div className="card">
      <div className="toolbar">
        <h2>
          Version {v.version} <span className={v.status === 'approved' ? 'badge ok' : 'badge'}>{STATUS_LABEL[v.status]}</span>
        </h2>
        {onEdit && <button onClick={onEdit}>Bearbeiten</button>}
        {onApprove && <button onClick={onApprove}>Freigeben</button>}
        {onRetire && (
          <button className="link danger" onClick={onRetire}>
            Zurückziehen
          </button>
        )}
        {onDelete && <DeleteButton onConfirm={onDelete} />}
      </div>
      <dl className="facts">
        <div>
          <dt>Typ</dt>
          <dd>{t.label}</dd>
        </div>
        {v.packageRef && (
          <div>
            <dt>Paket-ID</dt>
            <dd>
              <code>{v.packageRef}</code>
            </dd>
          </div>
        )}
        {t.file !== 'none' && (
          <div>
            <dt>Installationsdatei</dt>
            <dd>
              {v.file ? (
                <>
                  {v.file.name} ({fmtSize(v.file.sizeBytes)})
                  <div className="muted small" title="SHA-256 – wird vor jeder Ausführung auf Server und Gerät geprüft">
                    SHA-256 <code>{v.file.sha256}</code>
                  </div>
                </>
              ) : (
                <span className="error-text">fehlt</span>
              )}
              {onUpload && (
                <div>
                  <input type="file" onChange={(e) => e.target.files?.[0] && onUpload(e.target.files[0])} />
                </div>
              )}
            </dd>
          </div>
        )}
        {v.installArgs && (
          <div>
            <dt>Argumente</dt>
            <dd>
              <code>{v.installArgs}</code>
            </dd>
          </div>
        )}
        {v.productCode && (
          <div>
            <dt>MSI-Produktcode</dt>
            <dd>
              <code>{v.productCode}</code>
            </dd>
          </div>
        )}
        <div>
          <dt>Erkennung</dt>
          <dd>{v.detection.length ? v.detection.map((r, i) => <div key={i}>{ruleText(r)}</div>) : <span className="muted">keine – es wird immer installiert, ohne Nachprüfung</span>}</dd>
        </div>
        <div>
          <dt>Erfolg / Neustart</dt>
          <dd>
            Exitcodes {v.successCodes.join(', ')} / {v.rebootCodes.join(', ') || '–'}
          </dd>
        </div>
        <div>
          <dt>Timeout</dt>
          <dd>{Math.round(v.timeoutSeconds / 60)} min</dd>
        </div>
        {v.approvedAt && (
          <div>
            <dt>Freigegeben</dt>
            <dd>{fmtDate(v.approvedAt)}</dd>
          </div>
        )}
      </dl>
      {v.changeNote && <p className="muted">{v.changeNote}</p>}
      <p>
        <button className="link" onClick={() => setPreview(preview === 'install' ? null : 'install')}>
          Erzeugtes Installationsskript
        </button>{' '}
        ·{' '}
        <button className="link" onClick={() => setPreview(preview === 'uninstall' ? null : 'uninstall')}>
          Deinstallationsskript
        </button>
      </p>
      {preview && script.error && <div className="error">{script.error}</div>}
      {preview && script.data && (
        <>
          <p className="muted small">
            {script.data.interpreter} · {platform === 'windows' ? 'läuft als SYSTEM' : 'läuft als root'} · Hash wird vor der Ausführung geprüft
          </p>
          <pre className="code">{script.data.content}</pre>
        </>
      )}
    </div>
  );
}

export function ruleText(r: Rule): string {
  switch (r.type) {
    case 'software':
      return `Software „${r.name}“${r.version ? ` ${r.operator === 'eq' ? '=' : r.operator === 'lt' ? '<' : '≥'} ${r.version}` : ''}`;
    case 'file':
      return `Datei ${r.path}${r.version ? ` (Version ≥ ${r.version})` : ''}`;
    case 'registry':
      return `Registry ${r.key}${r.value ? ` \\ ${r.value}` : ''}${r.data ? ` = ${r.data}` : ''}`;
    case 'command':
      return `Befehl (Exitcode 0): ${r.command.split('\n')[0]}`;
  }
}

function VersionEditor({ platform, mode, value: f, onChange, onSave, onCancel }: { platform: Platform; mode: 'new' | 'edit'; value: VersionForm; onChange: (f: VersionForm) => void; onSave: () => void; onCancel: () => void }) {
  const t = TYPES[f.type];
  const types = (Object.keys(TYPES) as PackageType[]).filter((k) => !TYPES[k].platform || TYPES[k].platform === platform);
  const set = (patch: Partial<VersionForm>) => onChange({ ...f, ...patch });
  return (
    <div className="card highlight">
      <h2>{mode === 'new' ? 'Neue Version' : `Version ${f.version} bearbeiten`}</h2>
      <div className="form-grid">
        <label>
          Version
          <input value={f.version} onChange={(e) => set({ version: e.target.value })} required />
        </label>
        <label>
          Typ
          <select value={f.type} disabled={mode === 'edit'} onChange={(e) => set({ type: e.target.value as PackageType })}>
            {types.map((k) => (
              <option key={k} value={k}>
                {TYPES[k].label}
              </option>
            ))}
          </select>
        </label>
        {t.ref && (
          <label>
            Paket-ID
            <input value={f.packageRef} placeholder={t.ref} onChange={(e) => set({ packageRef: e.target.value })} />
          </label>
        )}
        {t.args && (
          <label>
            Argumente
            <input value={f.installArgs} placeholder={t.args} onChange={(e) => set({ installArgs: e.target.value })} />
          </label>
        )}
        {f.type === 'msi' && (
          <label>
            MSI-Produktcode (für Deinstallation ohne Datei)
            <input value={f.productCode} placeholder="{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" onChange={(e) => set({ productCode: e.target.value })} />
          </label>
        )}
        <label>
          Erfolgs-Exitcodes
          <input value={f.successCodes} onChange={(e) => set({ successCodes: e.target.value })} />
        </label>
        <label>
          Exitcodes „Neustart nötig“
          <input value={f.rebootCodes} onChange={(e) => set({ rebootCodes: e.target.value })} />
        </label>
        <label>
          Timeout (Sekunden)
          <input type="number" min={60} max={86400} value={f.timeoutSeconds} onChange={(e) => set({ timeoutSeconds: Number(e.target.value) })} />
        </label>
      </div>
      {f.type === 'script' && (
        <label>
          Installationsbefehl ({platform === 'windows' ? 'PowerShell' : 'bash'}; eine hochgeladene Datei steht in OPENCM_FILE_1)
          <textarea rows={6} className="mono" value={f.installCommand} onChange={(e) => set({ installCommand: e.target.value })} />
        </label>
      )}
      <label>
        Deinstallationsbefehl ({platform === 'windows' ? 'PowerShell' : 'bash'}){['exe', 'pkg', 'script'].includes(f.type) ? ' – für Deinstallation nötig' : ' – optional, sonst automatisch'}
        <textarea rows={3} className="mono" value={f.uninstallCommand} onChange={(e) => set({ uninstallCommand: e.target.value })} />
      </label>
      <h3>Erkennungsregeln</h3>
      <p className="muted small">Alle Regeln müssen zutreffen. Vor der Installation: schon erkannt → nichts zu tun. Danach: nicht erkannt → Fehler. Software-Regeln liefern außerdem den Installationsstand aus dem Inventar.</p>
      <RulesEditor platform={platform} value={f.detection} onChange={(detection) => set({ detection })} />
      <label>
        Änderungsnotiz
        <input value={f.changeNote} onChange={(e) => set({ changeNote: e.target.value })} />
      </label>
      {t.file !== 'none' && mode === 'new' && <p className="muted small">Die Installationsdatei wird nach dem Anlegen hochgeladen.</p>}
      <p>
        <button onClick={onSave}>Speichern</button>{' '}
        <button className="link" onClick={onCancel}>
          Abbrechen
        </button>
      </p>
    </div>
  );
}

function RulesEditor({ platform, value, onChange }: { platform: Platform; value: Rule[]; onChange: (r: Rule[]) => void }) {
  const set = (i: number, r: Rule) => onChange(value.map((x, j) => (i === j ? r : x)));
  const types: Rule['type'][] = platform === 'windows' ? ['software', 'file', 'registry', 'command'] : ['software', 'file', 'command'];
  const blank = (type: Rule['type']): Rule =>
    type === 'software' ? { type, name: '' } : type === 'file' ? { type, path: '' } : type === 'registry' ? { type, key: 'HKLM\\SOFTWARE\\' } : { type, command: '' };
  return (
    <div>
      {value.map((r, i) => (
        <div key={i} className="form-inline rule">
          <select value={r.type} onChange={(e) => set(i, blank(e.target.value as Rule['type']))}>
            {types.map((t) => (
              <option key={t} value={t}>
                {{ software: 'Software', file: 'Datei', registry: 'Registry', command: 'Befehl' }[t]}
              </option>
            ))}
          </select>
          {r.type === 'software' && (
            <>
              <input placeholder="Name (Platzhalter *), z. B. 7-Zip*" value={r.name} onChange={(e) => set(i, { ...r, name: e.target.value })} />
              <select value={r.operator ?? 'gte'} onChange={(e) => set(i, { ...r, operator: e.target.value as 'gte' })}>
                <option value="gte">≥</option>
                <option value="eq">=</option>
                <option value="lt">&lt;</option>
              </select>
              <input placeholder="Version (optional)" value={r.version ?? ''} onChange={(e) => set(i, { ...r, version: e.target.value || undefined })} style={{ width: '9rem' }} />
            </>
          )}
          {r.type === 'file' && (
            <>
              <input placeholder={platform === 'windows' ? '%ProgramFiles%\\7-Zip\\7z.exe' : '/usr/bin/htop'} value={r.path} onChange={(e) => set(i, { ...r, path: e.target.value })} />
              {platform === 'windows' && <input placeholder="min. Dateiversion" value={r.version ?? ''} onChange={(e) => set(i, { ...r, version: e.target.value || undefined })} style={{ width: '9rem' }} />}
            </>
          )}
          {r.type === 'registry' && (
            <>
              <input placeholder="HKLM\SOFTWARE\Hersteller\Produkt" value={r.key} onChange={(e) => set(i, { ...r, key: e.target.value })} />
              <input placeholder="Wert (optional)" value={r.value ?? ''} onChange={(e) => set(i, { ...r, value: e.target.value || undefined })} style={{ width: '9rem' }} />
              <input placeholder="Daten (optional)" value={r.data ?? ''} onChange={(e) => set(i, { ...r, data: e.target.value || undefined })} style={{ width: '9rem' }} />
            </>
          )}
          {r.type === 'command' && <input className="mono" placeholder="Exitcode 0 = installiert" value={r.command} onChange={(e) => set(i, { ...r, command: e.target.value })} />}
          <button className="link danger" onClick={() => onChange(value.filter((_, j) => j !== i))}>
            Entfernen
          </button>
        </div>
      ))}
      {value.length < 20 && (
        <button className="link" onClick={() => onChange([...value, blank('software')])}>
          + Regel
        </button>
      )}
    </div>
  );
}

function Compliance({ id }: { id: string }) {
  const c = useLoad(() => unwrap(api.GET('/packages/{id}/compliance', { params: { path: { id } } })), [id]);
  const [filter, setFilter] = useState<'all' | 'installed' | 'missing' | 'unknown' | 'failed'>('all');
  if (c.error) return <div className="error">{c.error}</div>;
  if (!c.data) return <div className="muted">Lade …</div>;
  const s = c.data.summary;
  const items = c.data.items.filter((i) =>
    filter === 'all'
      ? true
      : filter === 'installed'
        ? i.installed === true
        : filter === 'missing'
          ? i.installed === false
          : filter === 'unknown'
            ? i.installed === null
            : !!i.lastDeployment && ['failed', 'timeout'].includes(i.lastDeployment.status),
  );
  const tile = (k: typeof filter, label: string, n: number, cls = '') => (
    <button className={`tile ${cls} ${filter === k ? 'active' : ''}`} onClick={() => setFilter(filter === k ? 'all' : k)}>
      <span className="tile-value">{n}</span>
      <span className="tile-label">{label}</span>
    </button>
  );
  return (
    <>
      {!c.data.version && <p className="muted">Noch keine freigegebene Version – Erkennung erst nach der Freigabe.</p>}
      {c.data.version && <p className="muted">Erkennung anhand der Regeln von Version {c.data.version} und des letzten Inventars.</p>}
      <div className="tiles">
        {tile('all', 'Geräte', s.devices)}
        {tile('installed', 'installiert', s.installed, 'tile-ok')}
        {tile('missing', 'fehlt', s.missing, 'sev-tile-high')}
        {tile('unknown', 'unbekannt', s.unknown)}
        {tile('failed', 'Verteilung fehlgeschlagen', s.failed, 'tile-kev')}
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Gerät</th>
              <th>Installiert</th>
              <th>Letzte Verteilung</th>
            </tr>
          </thead>
          <tbody>
            {items.map((i) => (
              <tr key={i.deviceId}>
                <td>
                  <Link to={`/devices/${i.deviceId}`}>{i.hostname}</Link>
                </td>
                <td>{i.installed === true ? <span className="badge ok">ja</span> : i.installed === false ? <span className="badge danger">nein</span> : <span className="muted">unbekannt</span>}</td>
                <td>
                  {i.lastDeployment ? (
                    <>
                      {i.lastDeployment.action === 'install' ? 'Installation' : 'Deinstallation'} {i.lastDeployment.version}:{' '}
                      <span className={i.lastDeployment.status === 'succeeded' ? 'badge ok' : ['failed', 'timeout'].includes(i.lastDeployment.status) ? 'badge danger' : 'badge'}>{i.lastDeployment.status}</span>{' '}
                      <span className="muted small">{fmtDate(i.lastDeployment.finishedAt)}</span>
                    </>
                  ) : (
                    '–'
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function DeployForm({ packageName, version, platform, onCancel }: { packageName: string; version: Version; platform: Platform; onCancel: () => void }) {
  const navigate = useNavigate();
  const [action, setAction] = useState<'install' | 'uninstall'>('install');
  const [rings, setRings] = useState<Ring[]>(DEFAULT_RINGS.map((r) => ({ ...r, targets: { ...r.targets } })));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setError(null);
    setBusy(true);
    try {
      const r = await startDeployment({ kind: 'package', packageVersionId: version.id, action, rings });
      navigate(`/deployments/${r.id}`, { state: { approvalId: r.approvalId } });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card highlight">
      <h2>
        {packageName} {version.version} verteilen
      </h2>
      <div className="form-inline">
        <label className="check">
          <input type="radio" checked={action === 'install'} onChange={() => setAction('install')} /> installieren
        </label>
        <label className="check">
          <input type="radio" checked={action === 'uninstall'} onChange={() => setAction('uninstall')} /> deinstallieren
        </label>
      </div>
      <p className="muted small">Nur {PLATFORM_LABEL[platform]}-Geräte der Ziele werden berücksichtigt.</p>
      <RingsEditor value={rings} onChange={setRings} os={[platform]} />
      {error && <div className="error">{error}</div>}
      <p>
        <button disabled={busy || !rings.every((r) => hasTargets(r.targets) && r.name.trim())} onClick={() => void submit()}>
          Verteilung starten
        </button>{' '}
        <button className="link" onClick={onCancel}>
          Abbrechen
        </button>
      </p>
    </div>
  );
}
