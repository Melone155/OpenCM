import { readFileSync } from 'node:fs';
import type { Config } from '../config.ts';

/** Directory abstraction (LDAP/AD); tests use an in-memory implementation. */
export interface DirectoryUser {
  dn: string;
  username: string;
  displayName: string;
  email: string | null;
  /** group DNs (incl. nested groups when enabled) */
  groups: string[];
}

export interface Directory {
  /** Verifies credentials. Returns null for unknown users or wrong passwords. */
  authenticate(username: string, password: string): Promise<DirectoryUser | null>;
  /** Service-account bind and optional user lookup (no password check). */
  test(username?: string): Promise<{ ok: boolean; message: string; user?: DirectoryUser | null }>;
}

/** RFC 4515 escaping for values inserted into LDAP filters. */
export function ldapEscape(value: string): string {
  return value.replace(/[\\*()\0]/g, (c) => `\\${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
}

export function buildUserFilter(template: string, username: string): string {
  return template.split('{username}').join(ldapEscape(username));
}

const first = (v: unknown): string => (Array.isArray(v) ? String(v[0] ?? '') : v === undefined || v === null ? '' : Buffer.isBuffer(v) ? v.toString('utf8') : String(v));
const all = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : v ? [String(v)] : []);

export function createLdapDirectory(c: Config): Directory | null {
  if (!c.LDAP_URL) return null;
  if (!c.LDAP_BASE_DN) throw new Error('LDAP_BASE_DN is required when LDAP_URL is set');
  const tlsOptions = {
    minVersion: 'TLSv1.2' as const,
    rejectUnauthorized: !c.LDAP_TLS_INSECURE,
    ...(c.LDAP_CA_FILE && { ca: [readFileSync(c.LDAP_CA_FILE)] }),
  };

  async function client() {
    const { Client } = await import('ldapts');
    const cl = new Client({ url: c.LDAP_URL!, timeout: c.LDAP_TIMEOUT_MS, connectTimeout: c.LDAP_TIMEOUT_MS, tlsOptions });
    if (c.LDAP_STARTTLS) await cl.startTLS(tlsOptions);
    return cl;
  }

  async function lookup(username: string): Promise<DirectoryUser | null> {
    const cl = await client();
    try {
      if (c.LDAP_BIND_DN) await cl.bind(c.LDAP_BIND_DN, c.LDAP_BIND_PASSWORD ?? '');
      const attrs = [c.LDAP_USERNAME_ATTRIBUTE, c.LDAP_DISPLAYNAME_ATTRIBUTE, c.LDAP_EMAIL_ATTRIBUTE, 'memberOf'];
      const { searchEntries } = await cl.search(c.LDAP_BASE_DN!, { scope: 'sub', filter: buildUserFilter(c.LDAP_USER_FILTER, username), attributes: attrs, sizeLimit: 2 });
      if (searchEntries.length !== 1) return null; // unknown or ambiguous
      const e = searchEntries[0]!;
      let groups = all(e.memberOf);
      if (c.LDAP_NESTED_GROUPS) {
        // Active Directory: transitive membership via LDAP_MATCHING_RULE_IN_CHAIN
        try {
          const nested = await cl.search(c.LDAP_GROUP_BASE_DN ?? c.LDAP_BASE_DN!, {
            scope: 'sub',
            filter: `(member:1.2.840.113556.1.4.1941:=${ldapEscape(e.dn)})`,
            attributes: ['dn'],
          });
          groups = [...new Set([...groups, ...nested.searchEntries.map((g) => g.dn)])];
        } catch {
          // non-AD servers do not support the matching rule – memberOf is used
        }
      }
      return {
        dn: e.dn,
        username: first(e[c.LDAP_USERNAME_ATTRIBUTE]) || username,
        displayName: first(e[c.LDAP_DISPLAYNAME_ATTRIBUTE]),
        email: first(e[c.LDAP_EMAIL_ATTRIBUTE]) || null,
        groups,
      };
    } finally {
      await cl.unbind().catch(() => {});
    }
  }

  return {
    async authenticate(username, password) {
      // An empty password would be an "unauthenticated bind" which AD accepts – never allow it.
      if (!username || !password) return null;
      const user = await lookup(username);
      if (!user) return null;
      const cl = await client();
      try {
        await cl.bind(user.dn, password);
        return user;
      } catch {
        return null;
      } finally {
        await cl.unbind().catch(() => {});
      }
    },
    async test(username) {
      try {
        const user = username ? await lookup(username) : null;
        if (!username) {
          const cl = await client();
          try {
            if (c.LDAP_BIND_DN) await cl.bind(c.LDAP_BIND_DN, c.LDAP_BIND_PASSWORD ?? '');
          } finally {
            await cl.unbind().catch(() => {});
          }
        }
        return { ok: true, message: username ? (user ? 'User found' : 'User not found or ambiguous') : 'Bind successful', user };
      } catch (err) {
        return { ok: false, message: (err as Error).message };
      }
    },
  };
}
