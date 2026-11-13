import { useState } from 'react';
import { api, unwrap } from '../api/client';
import { useAuth } from '../auth';
import { useLoad } from '../hooks';

export function SecuritySettingsPage() {
  const { can } = useAuth();
  const s = useLoad(() => unwrap(api.GET('/settings/security')));
  const [threshold, setThreshold] = useState<number | null>(null);
  const [ldapUser, setLdapUser] = useState('');
  const [ldapResult, setLdapResult] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const edit = can('settings:update');

  async function patch(body: { mfaRequired?: boolean; fourEyes?: { enabled?: boolean; deviceThreshold?: number } }) {
    setError(null);
    try {
      await unwrap(api.PATCH('/settings/security', { body }));
      setMsg('Gespeichert.');
      await s.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function testLdap() {
    setLdapResult(null);
    try {
      const r = await unwrap(api.POST('/settings/ldap/test', { body: { username: ldapUser || undefined } }));
      setLdapResult(
        `${r.ok ? 'OK' : 'Fehler'}: ${r.message}` +
          (r.user ? `\nDN: ${r.user.dn}\nName: ${r.user.displayName}\nGruppen:\n  ${r.user.groups.join('\n  ') || '–'}` : ''),
      );
    } catch (e) {
      setLdapResult((e as Error).message);
    }
  }

  const d = s.data;
  if (!d) return <div className="muted">Lade …</div>;
  return (
    <>
      <h1>Sicherheit</h1>
      {msg && <div className="card">{msg}</div>}
      {error && <div className="error">{error}</div>}
      <div className="card">
        <h2>Vier-Augen-Prinzip</h2>
        <label className="check">
          <input type="checkbox" checked={d.fourEyes.enabled} disabled={!edit} onChange={(e) => void patch({ fourEyes: { enabled: e.target.checked } })} />
          Massenaktionen brauchen die Freigabe einer zweiten Person
        </label>
        <div className="form-inline">
          <label className="inline">
            ab
            <input
              type="number"
              min={0}
              disabled={!edit}
              value={threshold ?? d.fourEyes.deviceThreshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
              style={{ width: '6rem' }}
            />
            Geräten (0 = nur „Alle Geräte“)
          </label>
          {edit && threshold !== null && threshold !== d.fourEyes.deviceThreshold && (
            <button onClick={() => void patch({ fourEyes: { deviceThreshold: threshold } }).then(() => setThreshold(null))}>Übernehmen</button>
          )}
        </div>
        <p className="muted">Gilt für: Job ausführen, Ad-hoc-Skriptläufe, Behebungs-Jobs mit „sofort ausführen“ und das Aktivieren geplanter Jobs mit breitem Ziel.</p>
      </div>
      <div className="card">
        <h2>Zwei-Faktor-Anmeldung</h2>
        <label className="check">
          <input type="checkbox" checked={d.mfaRequired} disabled={!edit} onChange={(e) => void patch({ mfaRequired: e.target.checked })} />
          für alle Benutzer verpflichtend (ohne MFA ist nach der Anmeldung nur die Einrichtung möglich)
        </label>
      </div>
      <div className="card">
        <h2>LDAP / Active Directory</h2>
        {d.ldap.enabled ? (
          <>
            <p>
              Verbunden mit <code>{d.ldap.url}</code>. {d.ldap.requireGroup ? 'Anmelden dürfen nur Mitglieder gemappter Gruppen.' : 'Alle Verzeichnisbenutzer dürfen sich anmelden.'}
            </p>
            <p className="muted">AD-Gruppen werden unter System → Gruppen einer OpenCM-Gruppe zugeordnet (Feld „AD-Gruppe (DN)“).</p>
            {edit && (
              <div className="form-inline">
                <input placeholder="Benutzername zum Testen (optional)" value={ldapUser} onChange={(e) => setLdapUser(e.target.value)} />
                <button onClick={() => void testLdap()}>Verbindung testen</button>
              </div>
            )}
            {ldapResult && <pre className="code">{ldapResult}</pre>}
          </>
        ) : (
          <p className="muted">
            Nicht konfiguriert. Aktivieren über <code>LDAP_URL</code>, <code>LDAP_BIND_DN</code>, <code>LDAP_BIND_PASSWORD</code> und <code>LDAP_BASE_DN</code> in der <code>.env</code> (siehe Betriebshandbuch).
          </p>
        )}
      </div>
    </>
  );
}
