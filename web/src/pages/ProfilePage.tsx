import QRCode from 'qrcode';
import { useEffect, useState } from 'react';
import { api, unwrap } from '../api/client';
import { useAuth } from '../auth';
import { fmtDate, useLoad } from '../hooks';
import { DeleteButton } from './UsersPage';

export function MfaSection() {
  const { reload, me } = useAuth();
  const status = useLoad(() => unwrap(api.GET('/auth/mfa')));
  const [setup, setSetup] = useState<{ secret: string; otpauthUri: string; qr: string } | null>(null);
  const [code, setCode] = useState('');
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function start() {
    setError(null);
    try {
      const s = await unwrap(api.POST('/auth/mfa/setup'));
      setSetup({ ...s, qr: await QRCode.toDataURL(s.otpauthUri, { margin: 1, width: 200 }) });
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function act(p: Promise<{ recoveryCodes: string[] } | undefined>, done?: () => void) {
    setError(null);
    try {
      const r = await p;
      if (r?.recoveryCodes) setRecovery(r.recoveryCodes);
      setCode('');
      setSetup(null);
      done?.();
      await status.reload();
      await reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const s = status.data;
  return (
    <div className="card">
      <h2>Zwei-Faktor-Anmeldung (TOTP)</h2>
      {me?.mfaSetupRequired && <div className="card highlight">Für dein Konto ist eine Zwei-Faktor-Anmeldung vorgeschrieben. Bitte richte sie jetzt ein.</div>}
      {error && <div className="error">{error}</div>}
      {recovery && (
        <div className="card highlight">
          <strong>Wiederherstellungscodes – jetzt sicher aufbewahren, sie werden nur einmal angezeigt:</strong>
          <pre className="code">{recovery.join('\n')}</pre>
          <button className="link" onClick={() => setRecovery(null)}>
            Ich habe die Codes gesichert
          </button>
        </div>
      )}
      {s && !s.enabled && !setup && (
        <>
          <p>Mit einer Authenticator-App (z. B. Microsoft Authenticator, Google Authenticator, FreeOTP) wird bei jeder Anmeldung zusätzlich ein Code abgefragt.</p>
          <button onClick={() => void start()}>Einrichten</button>
        </>
      )}
      {setup && (
        <div className="mfa-setup">
          <img src={setup.qr} alt="QR-Code für die Authenticator-App" width={200} height={200} />
          <div>
            <p>QR-Code mit der App scannen oder den Schlüssel manuell eingeben:</p>
            <code className="secret">{setup.secret.replace(/(.{4})/g, '$1 ').trim()}</code>
            <div className="form-inline">
              <input placeholder="Code aus der App" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} />
              <button disabled={code.length < 6} onClick={() => void act(unwrap(api.POST('/auth/mfa/enable', { body: { code } })))}>
                Bestätigen
              </button>
            </div>
          </div>
        </div>
      )}
      {s?.enabled && (
        <>
          <p>
            <span className="badge ok">aktiv</span> · {s.recoveryCodesLeft} Wiederherstellungscodes übrig
          </p>
          <div className="form-inline">
            <input placeholder="aktueller Code" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} />
            <button className="link" disabled={code.length < 6} onClick={() => void act(unwrap(api.POST('/auth/mfa/recovery-codes', { body: { code } })))}>
              Neue Wiederherstellungscodes
            </button>
            {!s.required && (
              <button className="link danger" disabled={code.length < 6} onClick={() => void act(unwrap(api.POST('/auth/mfa/disable', { body: { code } })).then(() => undefined))}>
                Deaktivieren
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function ApiTokens() {
  const { me } = useAuth();
  const tokens = useLoad(() => unwrap(api.GET('/api-tokens')));
  const [name, setName] = useState('');
  const [perms, setPerms] = useState('');
  const [days, setDays] = useState(90);
  const [created, setCreated] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (me?.via === 'token') return null;

  async function create() {
    setError(null);
    try {
      const t = await unwrap(
        api.POST('/api-tokens', { body: { name, expiresInDays: days, permissions: perms.split(',').map((p) => p.trim()).filter(Boolean) } }),
      );
      setCreated(t.token);
      setName('');
      setPerms('');
      await tokens.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="card">
      <h2>API-Tokens</h2>
      <p className="muted">
        Für Skripte und Integrationen (<code>Authorization: Bearer oct_…</code>, CLI: <code>OPENCM_TOKEN</code>). Rechte = Schnittmenge aus Token-Rechten und deinen Rechten.
      </p>
      {error && <div className="error">{error}</div>}
      {created && (
        <div className="card highlight">
          <strong>Token – wird nur jetzt angezeigt:</strong>
          <pre className="code">{created}</pre>
          <button className="link" onClick={() => setCreated(null)}>
            Gespeichert
          </button>
        </div>
      )}
      <div className="form-inline">
        <input placeholder="Bezeichnung" value={name} onChange={(e) => setName(e.target.value)} />
        <input placeholder="Rechte, z. B. devices:read (leer = alle eigenen)" value={perms} onChange={(e) => setPerms(e.target.value)} />
        <label className="inline">
          gültig
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
            <option value={7}>7 Tage</option>
            <option value={30}>30 Tage</option>
            <option value={90}>90 Tage</option>
            <option value={365}>1 Jahr</option>
          </select>
        </label>
        <button disabled={!name} onClick={() => void create()}>
          Token erstellen
        </button>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Bezeichnung</th>
              <th>Rechte</th>
              <th>Läuft ab</th>
              <th>Zuletzt benutzt</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {tokens.data?.items.map((t) => (
              <tr key={t.id} className={t.revokedAt ? 'muted' : undefined}>
                <td>
                  {t.name} {t.revokedAt && <span className="badge">widerrufen</span>}
                </td>
                <td className="perms">{t.permissions.join(', ') || 'alle eigenen'}</td>
                <td>{fmtDate(t.expiresAt)}</td>
                <td>{fmtDate(t.lastUsedAt)}</td>
                <td className="actions">{!t.revokedAt && <DeleteButton onConfirm={() => unwrap(api.DELETE('/api-tokens/{id}', { params: { path: { id: t.id } } })).then(() => tokens.reload())} />}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function ProfilePage() {
  const { me } = useAuth();
  useEffect(() => {}, []);
  return (
    <>
      <h1>Mein Konto</h1>
      <div className="card">
        <dl className="facts">
          <div>
            <dt>Benutzer</dt>
            <dd>
              {me?.username} ({me?.authSource === 'ldap' ? 'Verzeichnis/AD' : 'lokal'})
            </dd>
          </div>
          <div>
            <dt>Globale Rechte</dt>
            <dd className="perms">{me?.permissions.join(', ') || '–'}</dd>
          </div>
          {me?.scoped.map((s, i) => (
            <div key={i}>
              <dt>Eingeschränkt auf {s.deviceGroupIds.length} Gerätegruppe(n)</dt>
              <dd className="perms">{s.permissions.join(', ')}</dd>
            </div>
          ))}
        </dl>
      </div>
      <MfaSection />
      <ApiTokens />
    </>
  );
}
