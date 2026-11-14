import { NavLink, Navigate, Route, Routes } from 'react-router-dom';
import { useAuth } from './auth';
import { AssetsPage } from './pages/AssetsPage';
import { SecurityPage } from './pages/SecurityPage';
import { AuditPage } from './pages/AuditPage';
import { Dashboard } from './pages/Dashboard';
import { CustomFieldsPage, DeviceGroupPage, DeviceGroupsPage } from './pages/DeviceGroupsPage';
import { DevicePage } from './pages/DevicePage';
import { DevicesPage } from './pages/DevicesPage';
import { DeploymentPage, DeploymentsPage } from './pages/DeploymentsPage';
import { PackagePage, PackagesPage } from './pages/PackagesPage';
import { PatchesPage } from './pages/PatchesPage';
import { LicensesPage } from './pages/LicensesPage';
import { ReportEditor, ReportsPage } from './pages/ReportsPage';
import { WebhooksPage } from './pages/WebhooksPage';
import { EnrollmentPage } from './pages/EnrollmentPage';
import { GroupsPage } from './pages/GroupsPage';
import { JobEditor } from './pages/JobEditor';
import { JobPage, RunPage } from './pages/JobPage';
import { JobsPage, RunsPage } from './pages/JobsPage';
import { LoginPage } from './pages/LoginPage';
import { MfaSection, ProfilePage } from './pages/ProfilePage';
import { RolesPage } from './pages/RolesPage';
import { ScriptPage } from './pages/ScriptPage';
import { ScriptsPage } from './pages/ScriptsPage';
import { SecuritySettingsPage } from './pages/SecuritySettingsPage';
import { SoftwarePage } from './pages/SoftwarePage';
import { UsersPage } from './pages/UsersPage';
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage';
import { VulnerabilityPage } from './pages/VulnerabilityPage';

interface NavItem {
  to: string;
  label: string;
  permission?: string | string[];
  /** device-related page: rights restricted to device groups suffice */
  scoped?: boolean;
}

const NAV: { section: string; items: NavItem[] }[] = [
  {
    section: 'Übersicht',
    items: [
      { to: '/', label: 'Dashboard' },
      { to: '/reports', label: 'Berichte', permission: 'reports:read' },
    ],
  },
  {
    section: 'Geräte',
    items: [
      { to: '/devices', label: 'Geräte', permission: 'devices:read', scoped: true },
      { to: '/device-groups', label: 'Gerätegruppen', permission: 'device_groups:read' },
      { to: '/assets', label: 'Assets (ohne Agent)', permission: 'assets:read' },
      { to: '/enrollment', label: 'Geräte hinzufügen', permission: 'devices:create' },
    ],
  },
  {
    section: 'Automatisierung',
    items: [
      { to: '/scripts', label: 'Skripte', permission: 'scripts:read' },
      { to: '/jobs', label: 'Jobs', permission: 'jobs:read' },
      { to: '/runs', label: 'Aktivität', permission: ['jobs:read', 'scripts:execute'], scoped: true },
    ],
  },
  {
    section: 'Sicherheit',
    items: [
      { to: '/security', label: 'Sicherheitsstatus', permission: 'inventory:read', scoped: true },
      { to: '/vulnerabilities', label: 'Schwachstellen', permission: 'vulnerabilities:read', scoped: true },
      { to: '/software', label: 'Software & Zuordnung', permission: 'inventory:read', scoped: true },
      { to: '/patches', label: 'Patches', permission: 'patches:read', scoped: true },
    ],
  },
  {
    section: 'Softwareverteilung',
    items: [
      { to: '/packages', label: 'Pakete', permission: 'software:read' },
      { to: '/deployments', label: 'Verteilungen', permission: ['software:read', 'patches:read'] },
      { to: '/licenses', label: 'Softwarelizenzen', permission: 'licenses:read' },
    ],
  },
  {
    section: 'System',
    items: [
      { to: '/users', label: 'Benutzer', permission: 'users:read' },
      { to: '/groups', label: 'Gruppen', permission: 'groups:read' },
      { to: '/roles', label: 'Rollen', permission: 'roles:read' },
      { to: '/custom-fields', label: 'Inventarfelder', permission: 'inventory:read' },
      { to: '/audit', label: 'Audit-Log', permission: 'audit:read' },
      { to: '/webhooks', label: 'Webhooks', permission: 'webhooks:read' },
      { to: '/settings/security', label: 'Sicherheit', permission: 'settings:read' },
    ],
  },
];

export function App() {
  const { me, loading, logout, can, canScoped } = useAuth();
  if (loading) return <div className="center muted">Lade …</div>;
  if (!me) return <LoginPage />;
  if (me.mfaSetupRequired) {
    // MFA is mandatory: nothing else is possible until it is set up
    return (
      <div className="center">
        <div style={{ width: 'min(640px, 100%)' }}>
          <MfaSection />
          <button className="link" onClick={() => void logout()}>
            Abmelden
          </button>
        </div>
      </div>
    );
  }
  const allowed = (p?: string | string[], scoped = false) => !p || [p].flat().some((x) => (scoped ? canScoped(x) : can(x)));

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><img src="/favicon.svg" alt="" width={24} height={24} />OpenCM</div>
        {NAV.map((s) => {
          const items = s.items.filter((i) => allowed(i.permission, i.scoped));
          if (!items.length) return null;
          return (
            <nav key={s.section}>
              <div className="nav-section">{s.section}</div>
              {items.map((i) => (
                <NavLink key={i.to} to={i.to} end={i.to === '/'} className="nav-link">
                  {i.label}
                </NavLink>
              ))}
            </nav>
          );
        })}
        <div className="sidebar-footer">
          <NavLink to="/profile" className="nav-link" title={me.username}>
            {me.displayName || me.username}
          </NavLink>
          <button className="link" onClick={() => void logout()}>
            Abmelden
          </button>
        </div>
      </aside>
      <main className="content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/profile" element={<ProfilePage />} />
          {canScoped('devices:read') && <Route path="/devices" element={<DevicesPage />} />}
          {canScoped('devices:read') && <Route path="/devices/:id" element={<DevicePage />} />}
          {can('devices:create') && <Route path="/enrollment" element={<EnrollmentPage />} />}
          {can('device_groups:read') && <Route path="/device-groups" element={<DeviceGroupsPage />} />}
          {can('device_groups:read') && <Route path="/device-groups/:id" element={<DeviceGroupPage />} />}
          {can('scripts:read') && <Route path="/scripts" element={<ScriptsPage />} />}
          {can('scripts:read') && <Route path="/scripts/:id" element={<ScriptPage />} />}
          {can('jobs:read') && <Route path="/jobs" element={<JobsPage />} />}
          {can('jobs:create') && <Route path="/jobs/new" element={<JobEditor />} />}
          {can('jobs:read') && <Route path="/jobs/:id" element={<JobPage />} />}
          {can('jobs:update') && <Route path="/jobs/:id/edit" element={<JobEditor />} />}
          {allowed(['jobs:read', 'scripts:execute'], true) && <Route path="/runs" element={<RunsPage />} />}
          {allowed(['jobs:read', 'scripts:execute'], true) && <Route path="/runs/:id" element={<RunPage />} />}
          {can('inventory:read') && <Route path="/custom-fields" element={<CustomFieldsPage />} />}
          {canScoped('vulnerabilities:read') && <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />}
          {canScoped('vulnerabilities:read') && <Route path="/vulnerabilities/:cveId" element={<VulnerabilityPage />} />}
          {canScoped('inventory:read') && <Route path="/software" element={<SoftwarePage />} />}
          {canScoped('inventory:read') && <Route path="/security" element={<SecurityPage />} />}
          {can('assets:read') && <Route path="/assets" element={<AssetsPage />} />}
          {canScoped('patches:read') && <Route path="/patches" element={<PatchesPage />} />}
          {can('reports:read') && <Route path="/reports" element={<ReportsPage />} />}
          {can('reports:read') && <Route path="/reports/:id" element={<ReportEditor />} />}
          {can('webhooks:read') && <Route path="/webhooks" element={<WebhooksPage />} />}
          {can('licenses:read') && <Route path="/licenses" element={<LicensesPage />} />}
          {can('software:read') && <Route path="/packages" element={<PackagesPage />} />}
          {can('software:read') && <Route path="/packages/:id" element={<PackagePage />} />}
          {allowed(['software:read', 'patches:read']) && <Route path="/deployments" element={<DeploymentsPage />} />}
          {allowed(['software:read', 'patches:read']) && <Route path="/deployments/:id" element={<DeploymentPage />} />}
          {can('users:read') && <Route path="/users" element={<UsersPage />} />}
          {can('groups:read') && <Route path="/groups" element={<GroupsPage />} />}
          {can('roles:read') && <Route path="/roles" element={<RolesPage />} />}
          {can('audit:read') && <Route path="/audit" element={<AuditPage />} />}
          {can('settings:read') && <Route path="/settings/security" element={<SecuritySettingsPage />} />}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
