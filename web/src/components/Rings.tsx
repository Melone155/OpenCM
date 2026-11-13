import { api, unwrap, type Schemas } from '../api/client';
import { useLoad } from '../hooks';
import { DevicePicker } from './forms';

export type Targets = { deviceIds: string[]; groupIds: string[]; allDevices: boolean };
export type Ring = { name: string; targets: Targets; delayHours: number; minSuccessPercent: number };

export const emptyTargets = (): Targets => ({ deviceIds: [], groupIds: [], allDevices: false });
export const DEFAULT_RINGS: Ring[] = [{ name: 'Alle', targets: { ...emptyTargets(), allDevices: true }, delayHours: 0, minSuccessPercent: 90 }];
export const STAGED_RINGS: Ring[] = [
  { name: 'Test', targets: emptyTargets(), delayHours: 0, minSuccessPercent: 100 },
  { name: 'Pilot', targets: emptyTargets(), delayHours: 24, minSuccessPercent: 90 },
  { name: 'Alle', targets: { ...emptyTargets(), allDevices: true }, delayHours: 24, minSuccessPercent: 90 },
];

export const hasTargets = (t: Targets) => t.allDevices || t.deviceIds.length > 0 || t.groupIds.length > 0;

/** All devices / device groups / individual devices. */
export function TargetPicker({ value, onChange, os }: { value: Targets; onChange: (t: Targets) => void; os?: string[] }) {
  const groups = useLoad(() => unwrap(api.GET('/device-groups')).catch(() => ({ items: [] as Schemas['DeviceGroup'][] })));
  return (
    <div>
      <label className="check">
        <input type="checkbox" checked={value.allDevices} onChange={(e) => onChange({ ...value, allDevices: e.target.checked })} />
        <strong>Alle Geräte</strong>
      </label>
      {!value.allDevices && (
        <div className="grid2">
          <div>
            <h4>Gerätegruppen</h4>
            {groups.data?.items.map((g) => (
              <label key={g.id} className="check">
                <input
                  type="checkbox"
                  checked={value.groupIds.includes(g.id)}
                  onChange={(e) => onChange({ ...value, groupIds: e.target.checked ? [...value.groupIds, g.id] : value.groupIds.filter((x) => x !== g.id) })}
                />
                {g.name}
              </label>
            ))}
            {groups.data?.items.length === 0 && <p className="muted">Keine Gruppen angelegt.</p>}
          </div>
          <div>
            <h4>Einzelne Geräte</h4>
            <DevicePicker selected={value.deviceIds} onChange={(deviceIds) => onChange({ ...value, deviceIds })} os={os} />
          </div>
        </div>
      )}
    </div>
  );
}

/** Editor for deployment rings (Test → Pilot → Alle). */
export function RingsEditor({ value, onChange, os }: { value: Ring[]; onChange: (r: Ring[]) => void; os?: string[] }) {
  const set = (i: number, r: Ring) => onChange(value.map((x, j) => (i === j ? r : x)));
  return (
    <div>
      <p className="muted">
        Ring für Ring: Der nächste Ring startet automatisch, wenn der vorige abgeschlossen ist, die Wartezeit vorbei ist und die Erfolgsquote erreicht wurde – sonst wird angehalten.
        Geräte, die schon in einem früheren Ring dran waren, werden nicht erneut adressiert.
      </p>
      <div className="form-inline">
        <button type="button" className="link" onClick={() => onChange(DEFAULT_RINGS.map((r) => ({ ...r, targets: { ...r.targets } })))}>
          Ein Ring (alle)
        </button>
        <button type="button" className="link" onClick={() => onChange(STAGED_RINGS.map((r) => ({ ...r, targets: { ...r.targets } })))}>
          Test → Pilot → Alle
        </button>
      </div>
      {value.map((r, i) => (
        <div key={i} className="card ring-edit">
          <div className="form-inline">
            <strong>Ring {i + 1}</strong>
            <input value={r.name} onChange={(e) => set(i, { ...r, name: e.target.value })} placeholder="Name" style={{ width: '10rem' }} />
            {i < value.length - 1 && (
              <>
                <label className="inline">
                  weiter nach
                  <input type="number" min={0} value={r.delayHours} onChange={(e) => set(i, { ...r, delayHours: Number(e.target.value) })} style={{ width: '5rem' }} />h
                </label>
                <label className="inline">
                  ab Erfolgsquote
                  <input type="number" min={0} max={100} value={r.minSuccessPercent} onChange={(e) => set(i, { ...r, minSuccessPercent: Number(e.target.value) })} style={{ width: '5rem' }} />%
                </label>
              </>
            )}
            {value.length > 1 && (
              <button type="button" className="link danger" onClick={() => onChange(value.filter((_, j) => j !== i))}>
                Entfernen
              </button>
            )}
          </div>
          <TargetPicker value={r.targets} onChange={(targets) => set(i, { ...r, targets })} os={os} />
          {!hasTargets(r.targets) && <div className="error-text small">Ring ohne Ziel</div>}
        </div>
      ))}
      {value.length < 10 && (
        <button type="button" className="link" onClick={() => onChange([...value, { name: `Ring ${value.length + 1}`, targets: emptyTargets(), delayHours: 0, minSuccessPercent: 90 }])}>
          + Ring
        </button>
      )}
    </div>
  );
}
