import { useState, type FormEvent } from 'react';
import { LoginError, useAuth } from '../auth';

export function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [needOtp, setNeedOtp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password, needOtp ? otp : undefined);
    } catch (err) {
      if (err instanceof LoginError && err.code === 'mfa_required') {
        setNeedOtp(true);
      } else {
        setError((err as Error).message);
        if (needOtp) setOtp('');
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center">
      <form className="card login" onSubmit={submit}>
        <h1>
          <picture>
            <source media="(prefers-color-scheme: dark)" srcSet="/logo-dark.svg" />
            <img src="/logo.svg" alt="OpenCM" width={250} height={64} />
          </picture>
        </h1>
        {!needOtp ? (
          <>
            <label>
              Benutzername
              <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" required />
            </label>
            <label>
              Passwort
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
            </label>
          </>
        ) : (
          <label>
            Code aus der Authenticator-App
            <input
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              autoFocus
              autoComplete="one-time-code"
              inputMode="numeric"
              placeholder="123456 oder Wiederherstellungscode"
              required
            />
          </label>
        )}
        {error && <div className="error">{error}</div>}
        <button type="submit" disabled={busy}>
          {busy ? 'Anmelden …' : needOtp ? 'Bestätigen' : 'Anmelden'}
        </button>
        {needOtp && (
          <button type="button" className="link" onClick={() => { setNeedOtp(false); setOtp(''); }}>
            Zurück
          </button>
        )}
      </form>
    </div>
  );
}
