import { Fragment, useState, type FormEvent } from 'react';
import { api, unwrap } from '../api/client';
import { useAuth } from '../auth';
import { RoleAssignmentsEditor } from '../components/RoleAssignments';
import { fmtDate, useLoad } from '../hooks';

export function UsersPage() {
  const { can, me } = useAuth();
  const [search, setSearch] = useState('');
  const users = useLoad(() => unwrap(api.GET('/users', { params: { query: { search: search || undefined, limit: 200 } } })), [search]);
  const roles = useLoad(() => (can('roles:read') ? unwrap(api.GET('/roles')) : Promise.resolve({ items: [] })));
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function act(p: Promise<unknown>) {
    setError(null);
    try {
      await p;
      await users.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <>
      <div className="toolbar">
        <h1>Benutzer</h1>
        <input placeholder="Suchen …" value={search} onChange={(e) => setSearch(e.target.value)} />
        {can('users:create') && <button onClick={() => setShowForm((v) => !v)}>Neuer Benutzer</button>}
      </div>
      {error && <div className="error">{error}</div>}
      {showForm && (
        <CreateUserForm
          roles={roles.data?.items ?? []}
          onDone={() => {
            setShowForm(false);
            void users.reload();
          }}
        />
      )}
      {users.error && <div className="error">{users.error}</div>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Benutzername</th>
              <th>Name</th>
              <th>Quelle</th>
              <th>Status</th>
              <th>MFA</th>
              <th>Letzte Anmeldung</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.data?.items.map((u) => (
              <Fragment key={u.id}>
                <tr>
                  <td>{u.username}</td>
                  <td>{u.displayName}</td>
                  <td>{u.authSource}</td>
                  <td>{u.isActive ? <span className="badge ok">aktiv</span> : <span className="badge">deaktiviert</span>}</td>
                  <td>{u.mfaEnabled ? <span className="badge ok">an</span> : <span className="muted">aus</span>}</td>
                  <td>{fmtDate(u.lastLoginAt)}</td>
                  <td className="actions">
                    {can('users:update') && (
                      <button className="link" onClick={() => setEditing(editing === u.id ? null : u.id)}>
                        {editing === u.id ? 'Schließen' : 'Rollen'}
                      </button>
                    )}
                    {can('users:update') && u.mfaEnabled && u.id !== me?.id && (
                      <ConfirmButton label="MFA zurücksetzen" confirm="MFA wirklich zurücksetzen?" onConfirm={() => act(unwrap(api.POST('/users/{id}/mfa/reset', { params: { path: { id: u.id } } })))} />
                    )}
                    {can('users:update') && u.id !== me?.id && (
                      <button className="link" onClick={() => void act(unwrap(api.PATCH('/users/{id}', { params: { path: { id: u.id } }, body: { isActive: !u.isActive } })))}>
                        {u.isActive ? 'Deaktivieren' : 'Aktivieren'}
                      </button>
                    )}
                    {can('users:delete') && u.id !== me?.id && (
                      <DeleteButton onConfirm={() => act(unwrap(api.DELETE('/users/{id}', { params: { path: { id: u.id } } })))} />
                    )}
                  </td>
                </tr>
                {editing === u.id && (
                  <tr>
                    <td colSpan={7}>
                      <UserRolesEditor id={u.id} onDone={() => setEditing(null)} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      {users.data && <div className="muted">{users.data.total} Benutzer</div>}
    </>
  );
}

function UserRolesEditor({ id, onDone }: { id: string; onDone: () => void }) {
  const detail = useLoad(() => unwrap(api.GET('/users/{id}', { params: { path: { id } } })), [id]);
  const d = detail.data;
  if (detail.error) return <div className="error">{detail.error}</div>;
  if (!d) return <div className="muted">Lade …</div>;
  return (
    <div>
      <p className="muted small">
        Direkt zugewiesene Rollen. Rollen aus Gruppen ({d.groups.map((g) => g.name).join(', ') || 'keine'}) kommen zusätzlich hinzu.
      </p>
      <RoleAssignmentsEditor
        value={d.roles.map((r) => ({ roleId: r.id, scopeDeviceGroupIds: r.scopeDeviceGroupIds ?? null }))}
        onSave={async (roleAssignments) => {
          await unwrap(api.PATCH('/users/{id}', { params: { path: { id } }, body: { roleAssignments } }));
          onDone();
        }}
        onCancel={onDone}
      />
    </div>
  );
}

/** Two-step confirmation (no browser confirm dialogs). */
export function ConfirmButton({ label, confirm, onConfirm, danger = true }: { label: string; confirm: string; onConfirm: () => Promise<unknown>; danger?: boolean }) {
  const [armed, setArmed] = useState(false);
  const cls = danger ? 'link danger' : 'link';
  return armed ? (
    <>
      <button className={cls} onClick={() => void onConfirm().finally(() => setArmed(false))}>
        {confirm}
      </button>
      <button className="link" onClick={() => setArmed(false)}>
        Abbrechen
      </button>
    </>
  ) : (
    <button className={cls} onClick={() => setArmed(true)}>
      {label}
    </button>
  );
}

export function DeleteButton({ onConfirm }: { onConfirm: () => Promise<unknown> }) {
  return <ConfirmButton label="Löschen" confirm="Wirklich löschen" onConfirm={onConfirm} />;
}

function CreateUserForm({ roles, onDone }: { roles: { id: string; name: string }[]; onDone: () => void }) {
  const [form, setForm] = useState({ username: '', displayName: '', email: '', password: '' });
  const [roleIds, setRoleIds] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      await unwrap(api.POST('/users', { body: { ...form, email: form.email || null, roleIds } }));
      onDone();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const field = (k: keyof typeof form, label: string, type = 'text') => (
    <label>
      {label}
      <input type={type} value={form[k]} onChange={(e) => setForm({ ...form, [k]: e.target.value })} required={k === 'username' || k === 'password'} />
    </label>
  );

  return (
    <form className="card form-grid" onSubmit={submit}>
      {field('username', 'Benutzername')}
      {field('displayName', 'Anzeigename')}
      {field('email', 'E-Mail', 'email')}
      {field('password', 'Passwort (min. 12 Zeichen)', 'password')}
      <fieldset>
        <legend>Rollen</legend>
        {roles.map((r) => (
          <label key={r.id} className="check">
            <input
              type="checkbox"
              checked={roleIds.includes(r.id)}
              onChange={(e) => setRoleIds(e.target.checked ? [...roleIds, r.id] : roleIds.filter((x) => x !== r.id))}
            />
            {r.name}
          </label>
        ))}
      </fieldset>
      {error && <div className="error">{error}</div>}
      <div>
        <button type="submit">Anlegen</button>
      </div>
    </form>
  );
}
