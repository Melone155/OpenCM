import { useState } from 'react';
import { api, unwrap, type Schemas } from '../api/client';
import { useAuth } from '../auth';
import { useLoad } from '../hooks';
import { DeleteButton } from './UsersPage';

type Role = Schemas['Role'];

export function RolesPage() {
  const { can } = useAuth();
  const roles = useLoad(() => unwrap(api.GET('/roles')));
  const catalog = useLoad(() => unwrap(api.GET('/permissions')));
  const [editing, setEditing] = useState<Role | 'new' | null>(null);
  const [error, setError] = useState<string | null>(null);

  return (
    <>
      <div className="toolbar">
        <h1>Rollen</h1>
        {can('roles:create') && <button onClick={() => setEditing('new')}>Neue Rolle</button>}
      </div>
      {(error || roles.error) && <div className="error">{error ?? roles.error}</div>}
      {editing && catalog.data && (
        <RoleEditor
          role={editing === 'new' ? null : editing}
          catalog={catalog.data}
          onDone={() => {
            setEditing(null);
            void roles.reload();
          }}
        />
      )}
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Beschreibung</th>
            <th>Rechte</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {roles.data?.items.map((r) => (
            <tr key={r.id}>
              <td>
                {r.name} {r.isSystem && <span className="badge">System</span>}
              </td>
              <td>{r.description}</td>
              <td className="perms">{r.permissions.join(', ') || '–'}</td>
              <td className="actions">
                {!r.isSystem && can('roles:update') && (
                  <button className="link" onClick={() => setEditing(r)}>
                    Bearbeiten
                  </button>
                )}
                {!r.isSystem && can('roles:delete') && (
                  <DeleteButton
                    onConfirm={() =>
                      unwrap(api.DELETE('/roles/{id}', { params: { path: { id: r.id } } }))
                        .then(() => roles.reload())
                        .catch((e: Error) => setError(e.message))
                    }
                  />
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

type Catalog = { actions: string[]; modules: { module: string; label: string; actions: string[] }[] };

function RoleEditor({ role, catalog, onDone }: { role: Role | null; catalog: Catalog; onDone: () => void }) {
  const [name, setName] = useState(role?.name ?? '');
  const [description, setDescription] = useState(role?.description ?? '');
  const [perms, setPerms] = useState<Set<string>>(new Set(role?.permissions ?? []));
  const [error, setError] = useState<string | null>(null);

  const toggle = (p: string) => {
    const next = new Set(perms);
    if (next.has(p)) next.delete(p);
    else next.add(p);
    setPerms(next);
  };

  async function save() {
    const body = { name, description, permissions: [...perms] };
    try {
      if (role) await unwrap(api.PATCH('/roles/{id}', { params: { path: { id: role.id } }, body }));
      else await unwrap(api.POST('/roles', { body }));
      onDone();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="card">
      <div className="form-grid">
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          Beschreibung
          <input value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
      </div>
      <div className="table-scroll">
        <table className="matrix">
          <thead>
            <tr>
              <th>Modul</th>
              {catalog.actions.map((a) => (
                <th key={a}>{a}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {catalog.modules.map((m) => (
              <tr key={m.module}>
                <td>{m.label}</td>
                {catalog.actions.map((a) => (
                  <td key={a}>
                    {m.actions.includes(a) && (
                      <input type="checkbox" checked={perms.has(`${m.module}:${a}`)} onChange={() => toggle(`${m.module}:${a}`)} />
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {error && <div className="error">{error}</div>}
      <button onClick={() => void save()}>Speichern</button>{' '}
      <button className="link" onClick={onDone}>
        Abbrechen
      </button>
    </div>
  );
}
