import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, setUnauthorizedHandler, type Me } from './api/client';

export class LoginError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

interface AuthState {
  me: Me | null;
  loading: boolean;
  login(username: string, password: string, otp?: string): Promise<void>;
  logout(): Promise<void>;
  reload(): Promise<void>;
  /** global permission */
  can(permission: string): boolean;
  /** permission globally or for some device groups (device-related pages) */
  canScoped(permission: string): boolean;
}

const AuthContext = createContext<AuthState | null>(null);

/** Same semantics as server/src/auth/permissions.ts → grantMatches */
export function grantMatches(grant: string, required: string): boolean {
  if (grant === '*' || grant === required) return true;
  const [mod, action] = grant.split(':');
  return action === '*' && required.startsWith(`${mod}:`);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async () => {
    const { data } = await api.GET('/auth/me');
    setMe(data ?? null);
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => setMe(null));
    void reload().finally(() => setLoading(false));
  }, [reload]);

  const login = useCallback(async (username: string, password: string, otp?: string) => {
    const { data, error } = await api.POST('/auth/login', { body: { username, password, ...(otp && { otp }) } });
    if (error) {
      const e = error as { error?: { code?: string; message?: string } };
      throw new LoginError(e.error?.code ?? 'error', e.error?.message ?? 'Anmeldung fehlgeschlagen');
    }
    setMe(data.user);
  }, []);

  const logout = useCallback(async () => {
    await api.POST('/auth/logout');
    setMe(null);
  }, []);

  const can = useCallback((p: string) => !!me?.permissions.some((g) => grantMatches(g, p)), [me]);
  const canScoped = useCallback((p: string) => can(p) || !!me?.scoped.some((s) => s.permissions.some((g) => grantMatches(g, p))), [me, can]);

  const value = useMemo(() => ({ me, loading, login, logout, reload, can, canScoped }), [me, loading, login, logout, reload, can, canScoped]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth outside AuthProvider');
  return ctx;
}
