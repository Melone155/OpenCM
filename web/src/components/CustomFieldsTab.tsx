import { useState } from 'react';
import { api, unwrap } from '../api/client';
import { useAuth } from '../auth';
import { fmtDate, useLoad } from '../hooks';

export function CustomFieldsTab({ deviceId }: { deviceId: string }) {
  const { can } = useAuth();
  const values = useLoad(() => unwrap(api.GET('/devices/{id}/custom-fields', { params: { path: { id: deviceId } } })), [deviceId]);
  const [editing, setEditing] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  async function save(fieldId: string, type: string) {
    const raw = editing[fieldId] ?? '';
    setError(null);
    try {
      if (raw === '') await unwrap(api.DELETE('/devices/{id}/custom-fields/{fieldId}', { params: { path: { id: deviceId, fieldId } } }));
      else
        await unwrap(
          api.PUT('/devices/{id}/custom-fields/{fieldId}', {
            params: { path: { id: deviceId, fieldId } },
            body: { value: type === 'number' ? Number(raw) : type === 'boolean' ? raw === 'true' : raw },
          }),
        );
      setEditing(({ [fieldId]: _, ...rest }) => rest);
      await values.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  if (values.data && values.data.items.length === 0) return <p className="muted">Keine eigenen Felder definiert (System → Inventarfelder).</p>;
  return (
    <>
      {error && <div className="error">{error}</div>}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Feld</th>
              <th>Wert</th>
              <th>Quelle</th>
              <th>Aktualisiert</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {values.data?.items.map((f) => (
              <tr key={f.fieldId}>
                <td>
                  {f.label} <span className="muted">({f.type})</span>
                </td>
                <td>
                  {editing[f.fieldId] !== undefined ? (
                    f.type === 'boolean' ? (
                      <select value={editing[f.fieldId]} onChange={(e) => setEditing({ ...editing, [f.fieldId]: e.target.value })}>
                        <option value="">–</option>
                        <option value="true">ja</option>
                        <option value="false">nein</option>
                      </select>
                    ) : (
                      <input
                        type={f.type === 'number' ? 'number' : f.type === 'date' ? 'date' : 'text'}
                        value={editing[f.fieldId]}
                        onChange={(e) => setEditing({ ...editing, [f.fieldId]: e.target.value })}
                      />
                    )
                  ) : (
                    (f.value ?? '–')
                  )}
                </td>
                <td>{f.source === 'script' ? 'Skript' : f.source === 'manual' ? 'manuell' : '–'}</td>
                <td>{fmtDate(f.updatedAt)}</td>
                <td className="actions">
                  {can('inventory:update') &&
                    (editing[f.fieldId] !== undefined ? (
                      <>
                        <button className="link" onClick={() => void save(f.fieldId, f.type)}>
                          Speichern
                        </button>
                        <button className="link" onClick={() => setEditing(({ [f.fieldId]: _, ...rest }) => rest)}>
                          Abbrechen
                        </button>
                      </>
                    ) : (
                      <button className="link" onClick={() => setEditing({ ...editing, [f.fieldId]: f.value ?? '' })}>
                        Bearbeiten
                      </button>
                    ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
