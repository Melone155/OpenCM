import type { ScriptParameter } from '../db/schema.ts';

/**
 * Script templates (e.g. for vulnerability remediation). Importing a template
 * creates a normal script in status "draft" – it must be reviewed and approved
 * before it can run anywhere.
 */
export interface ScriptTemplate {
  id: string;
  name: string;
  description: string;
  interpreter: 'powershell' | 'cmd' | 'bash' | 'zsh' | 'python';
  category: 'remediation' | 'maintenance';
  parameters: ScriptParameter[];
  content: string;
}

export const SCRIPT_TEMPLATES: ScriptTemplate[] = [
  {
    id: 'win-winget-upgrade',
    name: 'Windows: Software per winget aktualisieren',
    description: 'Aktualisiert ein Paket über winget im Systemkontext (z. B. Mozilla.Firefox, 7zip.7zip, Notepad++.Notepad++).',
    interpreter: 'powershell',
    category: 'remediation',
    parameters: [{ name: 'PackageId', label: 'winget-Paket-ID', type: 'string', required: true }],
    content: `$ErrorActionPreference = 'Stop'
$id = $env:OPENCM_PARAM_PACKAGEID
# winget is not on PATH for SYSTEM – locate the App Installer binary
$winget = Get-ChildItem "$env:ProgramFiles\\WindowsApps\\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\\winget.exe" -ErrorAction SilentlyContinue |
  Sort-Object FullName -Descending | Select-Object -First 1
if (-not $winget) { Write-Error 'winget (App Installer) ist nicht installiert'; exit 2 }
Write-Output "Aktualisiere $id mit $($winget.FullName)"
& $winget.FullName upgrade --id $id --exact --silent --disable-interactivity --accept-package-agreements --accept-source-agreements --scope machine
$code = $LASTEXITCODE
# 0x8A15002B = no applicable update (already current)
if ($code -eq -1978335189) { Write-Output 'Bereits aktuell.'; exit 0 }
exit $code
`,
  },
  {
    id: 'win-uninstall',
    name: 'Windows: Software deinstallieren (MSI/Registry)',
    description: 'Deinstalliert Programme, deren Anzeigename dem Muster entspricht (Platzhalter *). Mit DryRun wird nur angezeigt.',
    interpreter: 'powershell',
    category: 'remediation',
    parameters: [
      { name: 'DisplayName', label: 'Anzeigename (Platzhalter *)', type: 'string', required: true },
      { name: 'DryRun', label: 'Nur anzeigen', type: 'boolean', required: false, default: true },
    ],
    content: `$ErrorActionPreference = 'Stop'
$pattern = $env:OPENCM_PARAM_DISPLAYNAME
$dry = $env:OPENCM_PARAM_DRYRUN -eq 'true'
$keys = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
$apps = @(Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like $pattern })
if (-not $apps) { Write-Output "Nichts gefunden für '$pattern'."; exit 0 }
$failed = 0
foreach ($a in $apps) {
  Write-Output "Gefunden: $($a.DisplayName) $($a.DisplayVersion)"
  if ($dry) { continue }
  if ($a.PSChildName -match '^\\{[0-9A-Fa-f-]+\\}$' -and $a.WindowsInstaller -eq 1) {
    $p = Start-Process msiexec.exe -ArgumentList "/x $($a.PSChildName) /qn /norestart" -Wait -PassThru
  } elseif ($a.QuietUninstallString) {
    $p = Start-Process cmd.exe -ArgumentList "/c $($a.QuietUninstallString)" -Wait -PassThru
  } else {
    Write-Warning "Keine stille Deinstallation verfügbar: $($a.UninstallString)"; $failed++; continue
  }
  Write-Output "  Exitcode $($p.ExitCode)"
  if ($p.ExitCode -notin 0, 1605, 3010) { $failed++ }
}
exit $failed
`,
  },
  {
    id: 'win-choco-upgrade',
    name: 'Windows: Chocolatey-Paket aktualisieren',
    description: 'choco upgrade für ein Paket (Chocolatey muss installiert sein).',
    interpreter: 'powershell',
    category: 'remediation',
    parameters: [{ name: 'Package', label: 'Paketname', type: 'string', required: true }],
    content: `$choco = Join-Path $env:ProgramData 'chocolatey\\bin\\choco.exe'
if (-not (Test-Path $choco)) { Write-Error 'Chocolatey ist nicht installiert'; exit 2 }
& $choco upgrade $env:OPENCM_PARAM_PACKAGE -y --no-progress
exit $LASTEXITCODE
`,
  },
  {
    id: 'linux-apt-upgrade',
    name: 'Linux (apt): Paket aktualisieren',
    description: 'Aktualisiert ein Paket auf Debian/Ubuntu (nur wenn installiert).',
    interpreter: 'bash',
    category: 'remediation',
    parameters: [{ name: 'Package', label: 'Paketname', type: 'string', required: true }],
    content: `set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
pkg="$OPENCM_PARAM_PACKAGE"
apt-get update -qq
apt-get install -y --only-upgrade -o Dpkg::Options::=--force-confold "$pkg"
dpkg-query -W -f='\${Package} \${Version}\\n' "$pkg"
`,
  },
  {
    id: 'linux-dnf-upgrade',
    name: 'Linux (dnf/yum): Paket aktualisieren',
    description: 'Aktualisiert ein Paket auf RHEL/Rocky/Alma/Fedora.',
    interpreter: 'bash',
    category: 'remediation',
    parameters: [{ name: 'Package', label: 'Paketname', type: 'string', required: true }],
    content: `set -euo pipefail
pkg="$OPENCM_PARAM_PACKAGE"
if command -v dnf >/dev/null; then dnf -y upgrade "$pkg"; else yum -y update "$pkg"; fi
rpm -q "$pkg"
`,
  },
  {
    id: 'macos-softwareupdate',
    name: 'macOS: Systemupdates installieren',
    description: 'Installiert alle empfohlenen macOS-Updates (ohne Neustart).',
    interpreter: 'zsh',
    category: 'remediation',
    parameters: [],
    content: `softwareupdate --install --recommended --agree-to-license
`,
  },
];
