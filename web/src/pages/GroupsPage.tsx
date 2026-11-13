import { Fragment, useState, type FormEvent } from 'react';
import { api, unwrap } from '../api/client';
import { useAuth } from '../auth';
import { RoleAssignmentsEditor } from '../components/RoleAssignments';
import { useLoad } from '../hooks';
import { DeleteButton } from './UsersPage';

export function GroupsPage() {
  const { can } = useAuth();
  const groups = useLoad(() => unwrap(api.GET('/groups')));
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [ldapGroup, setLdapGroup] = useState('');
  const [editing, setEditing] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function create(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await unwrap(api.POST('/groups', { body: { name, description, ldapGroup: ldapGroup.trim() || null } }));
      setName('');
      setDescription('');
      setLdapGroup('');
      await groups.reload();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <>
      <h1>Benutzergruppen</h1>
      {(error || groups.error) && <div className="error">{error ?? groups.error}</div>}
      {can('groups:create') && (
        <form className="card form-inline" onSubmit={create}>
          <input placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} required />
          <input placeholder="Beschreibung" value={description} onChange={(e) => setDescription(e.target.value)} />
          <input placeholder="AD-Gruppe (DN, optional)" value={ldapGroup} onChange={(e) => setLdapGroup(e.target.value)} />
          <button type="submit">Gruppe anlegen</button>
        </form>
      )}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Beschreibung</th>
              <th>AD-Gruppe (DN)</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {groups.data?.items.map((g) => (
              <Fragment key={g.id}>
                <tr>
                  <td>{g.name}</td>
                  <td>{g.description}</td>
                  <td className="small">{g.ldapGroup ?? <span className="muted">–</span>}</td>
                  <td className="actions">
                    {can('groups:update') && (
                      <button className="link" onClick={() => setEditing(editing === g.id ? null : g.id)}>
                        {editing === g.id ? 'Schließen' : 'Bearbeiten'}
                      </button>
                    )}
                    {can('groups:delete') && (
                      <DeleteButton
                        onConfirm={() =>
                          unwrap(api.DELETE('/groups/{id}', { params: { path: { id: g.id } } }))
                            .then(() => groups.reload())
                            .catch((e: Error) => setError(e.message))
                        }
                      />
                    )}
                  </td>
                </tr>
                {editing === g.id && (
                  <tr>
                    <td colSpan={4}>
                      <GroupEditor
                        id={g.id}
                        onDone={() => {
                          setEditing(null);
                          void groups.reload();
                        }}
                      />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted">
        Mitglieder einer Gruppe mit AD-Gruppe werden bei jeder Anmeldung aus dem Verzeichnis abgeglichen. Rollen können global oder nur für bestimmte Gerätegruppen gelten.
      </p>
    </>
  );
}

function GroupEditor({ id, onDone }: { id: string; onDone: () => void }) {
  const detail = useLoad(() => unwrap(api.GET('/groups/{id}', { params: { path: { id } } })), [id]);
  const [ldap, setLdap] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const d = detail.data;
  if (detail.error) return <div className="error">{detail.error}</div>;
  if (!d) return <div className="muted">Lade …</div>;

  async function saveLdap() {
    setError(null);
    try {
      await unwrap(api.PATCH('/groups/{id}', { params: { path: { id } }, body: { ldapGroup: (ldap ?? '').trim() || null } }));
      onDone();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div>
      <div className="form-inline">
        <label className="inline">
          AD-Gruppe (DN)
          <input style={{ minWidth: '24rem', maxWidth: '100%' }} value={ldap ?? d.ldapGroup ?? ''} onChange={(e) => setLdap(e.target.value)} placeholder="CN=OpenCM-Admins,OU=Gruppen,DC=firma,DC=local" />
        </label>
        {ldap !== null && <button onClick={() => void saveLdap()}>Übernehmen</button>}
      </div>
      {error && <div className="error">{error}</div>}
      <p className="muted small">Mitglieder: {d.members.map((m) => m.username).join(', ') || '–'}</p>
      <h3>Rollen</h3>
      <RoleAssignmentsEditor
        value={d.roles.map((r) => ({ roleId: r.id, scopeDeviceGroupIds: r.scopeDeviceGroupIds ?? null }))}
        onSave={async (roleAssignments) => {
          await unwrap(api.PATCH('/groups/{id}', { params: { path: { id } }, body: { roleAssignments } }));
          onDone();
        }}
        onCancel={onDone}
      />
    </div>
  );
}
