import { useState } from 'react';
import { api, unwrap } from '../api/client';
import { useLoad } from '../hooks';

export interface Assignment {
  roleId: string;
  scopeDeviceGroupIds: string[] | null;
}

/** Editor for role assignments with optional device-group scope. */
export function RoleAssignmentsEditor({ value, onSave, onCancel }: { value: Assignment[]; onSave: (a: Assignment[]) => Promise<void>; onCancel: () => void }) {
  const roles = useLoad(() => unwrap(api.GET('/roles')));
  const groups = useLoad(() => unwrap(api.GET('/device-groups')).catch(() => ({ items: [] })));
  const [items, setItems] = useState<Assignment[]>(value);
  const [error, setError] = useState<string | null>(null);
  const update = (i: number, a: Assignment) => setItems(items.map((x, j) => (i === j ? a : x)));

  return (
    <div className="card highlight">
      {items.map((a, i) => (
        <div key={i} className="form-inline rule">
          <select value={a.roleId} onChange={(e) => update(i, { ...a, roleId: e.target.value })}>
            {roles.data?.items.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </select>
          <select value={a.scopeDeviceGroupIds ? 'scoped' : 'global'} onChange={(e) => update(i, { ...a, scopeDeviceGroupIds: e.target.value === 'global' ? null : [] })}>
            <option value="global">auf alle Geräte</option>
            <option value="scoped">nur auf Gerätegruppen …</option>
          </select>
          {a.scopeDeviceGroupIds && (
            <span className="scope-groups">
              {groups.data?.items.map((g) => (
                <label key={g.id} className="check">
                  <input
                    type="checkbox"
                    checked={a.scopeDeviceGroupIds!.includes(g.id)}
                    onChange={(e) =>
                      update(i, { ...a, scopeDeviceGroupIds: e.target.checked ? [...a.scopeDeviceGroupIds!, g.id] : a.scopeDeviceGroupIds!.filter((x) => x !== g.id) })
                    }
                  />
                  {g.name}
                </label>
              ))}
            </span>
          )}
          <button className="link danger" onClick={() => setItems(items.filter((_, j) => j !== i))}>
            Entfernen
          </button>
        </div>
      ))}
      <button className="link" disabled={!roles.data?.items.length} onClick={() => setItems([...items, { roleId: roles.data!.items[0]!.id, scopeDeviceGroupIds: null }])}>
        + Rolle
      </button>
      {error && <div className="error">{error}</div>}
      <p>
        <button
          onClick={() =>
            void onSave(items).catch((e: Error) => setError(e.message))
          }
        >
          Speichern
        </button>{' '}
        <button className="link" onClick={onCancel}>
          Abbrechen
        </button>
      </p>
    </div>
  );
}
