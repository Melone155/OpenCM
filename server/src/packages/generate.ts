/**
 * Turns a package version into a script step for the existing task engine.
 *
 * Every value that comes from the package definition is embedded as a quoted
 * literal (PowerShell single quotes / POSIX single quotes) – never interpolated.
 * Package references are additionally restricted to a safe character set.
 */
import { createHash } from 'node:crypto';
import type { DetectionRule, RunFile, RunStep } from '../db/schema.ts';

export type Platform = 'windows' | 'linux' | 'macos';
export type PackageType = 'msi' | 'exe' | 'winget' | 'choco' | 'deb' | 'rpm' | 'apt' | 'dnf' | 'pkg' | 'brew' | 'script';
export type PackageAction = 'install' | 'uninstall';

export const PACKAGE_TYPES: Record<PackageType, { platform: Platform | null; file: 'required' | 'optional' | 'none'; ref: 'required' | 'optional' | 'none'; label: string }> = {
  msi: { platform: 'windows', file: 'required', ref: 'none', label: 'MSI-Paket' },
  exe: { platform: 'windows', file: 'required', ref: 'none', label: 'EXE-Installer' },
  winget: { platform: 'windows', file: 'none', ref: 'required', label: 'winget' },
  choco: { platform: 'windows', file: 'none', ref: 'required', label: 'Chocolatey' },
  deb: { platform: 'linux', file: 'required', ref: 'required', label: 'DEB-Datei' },
  rpm: { platform: 'linux', file: 'required', ref: 'required', label: 'RPM-Datei' },
  apt: { platform: 'linux', file: 'none', ref: 'required', label: 'apt-Paket' },
  dnf: { platform: 'linux', file: 'none', ref: 'required', label: 'dnf-Paket' },
  pkg: { platform: 'macos', file: 'required', ref: 'none', label: 'macOS-PKG' },
  brew: { platform: 'macos', file: 'none', ref: 'required', label: 'Homebrew' },
  script: { platform: null, file: 'optional', ref: 'none', label: 'Eigene Befehle' },
};

/** Package ids for winget/choco/apt/dnf/brew and package names for deb/rpm. */
export const PACKAGE_REF = /^[A-Za-z0-9][A-Za-z0-9._+:@\/-]{0,199}$/;

export interface PackageVersionInput {
  type: PackageType;
  fileSha256: string | null;
  fileName: string | null;
  fileSize?: number | null;
  packageRef: string | null;
  installArgs: string;
  installCommand: string;
  uninstallCommand: string;
  productCode: string | null;
  detection: DetectionRule[];
  successCodes: number[];
  rebootCodes: number[];
}

export interface PackageInfo {
  id: string;
  name: string;
  platform: Platform;
}

/** Validation independent of the database. Returns human-readable problems (German, shown in the UI). */
export function validatePackageVersion(platform: Platform, v: PackageVersionInput, opts: { requireFile?: boolean } = {}): string[] {
  const errors: string[] = [];
  const t = PACKAGE_TYPES[v.type];
  if (!t) return [`Unbekannter Pakettyp "${v.type}"`];
  if (t.platform && t.platform !== platform) errors.push(`Typ ${v.type} gibt es nur für ${t.platform}`);
  if (t.ref === 'required' && !v.packageRef) errors.push('Paket-ID/-Name fehlt');
  if (v.packageRef && !PACKAGE_REF.test(v.packageRef)) errors.push('Paket-ID enthält unzulässige Zeichen');
  if (t.ref === 'none' && v.packageRef && v.type !== 'script') errors.push(`Typ ${v.type} hat keine Paket-ID`);
  if (opts.requireFile && t.file === 'required' && !v.fileSha256) errors.push('Installationsdatei fehlt (hochladen)');
  if (t.file === 'none' && v.fileSha256) errors.push(`Typ ${v.type} hat keine Installationsdatei`);
  if (v.type === 'script' && !v.installCommand.trim()) errors.push('Installationsbefehl fehlt');
  if (v.productCode && !/^\{[0-9A-Fa-f-]{36}\}$/.test(v.productCode)) errors.push('MSI-Produktcode muss die Form {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} haben');
  if (!v.successCodes.length) errors.push('Mindestens ein Erfolgs-Exitcode nötig');
  for (const r of v.detection) {
    if (r.type === 'registry' && platform !== 'windows') errors.push('Registry-Regeln gibt es nur unter Windows');
    if (r.type === 'software' && !r.name.trim()) errors.push('Software-Regel ohne Namen');
    if (r.type === 'software' && r.version && !/\d/.test(r.version)) errors.push('Software-Regel: Version muss Ziffern enthalten');
    if (r.type === 'file' && !r.path.trim()) errors.push('Datei-Regel ohne Pfad');
    if (r.type === 'file' && r.version && platform !== 'windows') errors.push('Dateiversionen werden nur unter Windows geprüft');
    if (r.type === 'registry' && !/^(HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT|HKU|HKEY_USERS)\\/i.test(r.key)) errors.push('Registry-Schlüssel muss mit HKLM\\ (o. ä.) beginnen');
    if (r.type === 'command' && !r.command.trim()) errors.push('Befehls-Regel ohne Befehl');
  }
  return errors;
}

/** Problems that only matter for a given action (e.g. EXE uninstall needs a command). */
export function validateAction(v: PackageVersionInput, action: PackageAction): string[] {
  if (action === 'install') return [];
  if (v.uninstallCommand.trim()) return [];
  switch (v.type) {
    case 'exe':
    case 'pkg':
    case 'script':
      return [`Für ${v.type} ist ein Deinstallationsbefehl nötig`];
    default:
      return [];
  }
}

// ---------------------------------------------------------------- quoting helpers

/** PowerShell single-quoted literal. PowerShell also treats typographic single quotes as quotes. */
export function psq(s: string): string {
  return `'${s.replace(/['‘’‚‛]/g, (m) => m + m)}'`;
}

/** POSIX shell single-quoted literal. */
export function shq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Splits "a b \"c d\" 'e f'" into arguments (no variable expansion, no escapes besides quotes). */
export function splitArgs(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: '"' | "'" | null = null;
  let has = false;
  for (const ch of s) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      has = true;
    } else if (/\s/.test(ch)) {
      if (has || cur) out.push(cur);
      cur = '';
      has = false;
    } else {
      cur += ch;
      has = true;
    }
  }
  if (has || cur) out.push(cur);
  return out;
}

/** Glob (*, ?) → anchored, case-insensitive-usable regex that works in JS, .NET and POSIX ERE/awk. */
export function globToRegex(glob: string): string {
  let re = '';
  for (const ch of glob) {
    if (ch === '*') re += '.*';
    else if (ch === '?') re += '.';
    else if (/[\\^$.|+()[\]{}]/.test(ch)) re += `\\${ch}`;
    else re += ch;
  }
  return `^${re}$`;
}

const utf16b64 = (s: string) => Buffer.from(s, 'utf16le').toString('base64');

// ---------------------------------------------------------------- PowerShell

const PS_HEADER = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Exit-OpenCM([string]$Message, [int]$Code) { [Console]::Error.WriteLine($Message); exit $Code }
function Compare-OpenCMVersion([string]$A, [string]$B) {
  $x = @([regex]::Matches($A, '\\d+|[A-Za-z]+') | ForEach-Object { $_.Value })
  $y = @([regex]::Matches($B, '\\d+|[A-Za-z]+') | ForEach-Object { $_.Value })
  for ($i = 0; $i -lt [Math]::Max($x.Count, $y.Count); $i++) {
    if ($i -ge $x.Count) { if ($y[$i] -match '^\\d') { return -1 } else { return 1 } }
    if ($i -ge $y.Count) { if ($x[$i] -match '^\\d') { return 1 } else { return -1 } }
    $xn = $x[$i] -match '^\\d'; $yn = $y[$i] -match '^\\d'
    if ($xn -and $yn) { $c = ([decimal]$x[$i]).CompareTo([decimal]$y[$i]) }
    elseif ($xn -ne $yn) { if ($xn) { $c = 1 } else { $c = -1 } }
    else { $c = [string]::Compare($x[$i], $y[$i], $true) }
    if ($c -ne 0) { return [Math]::Sign($c) }
  }
  return 0
}
function Invoke-OpenCMChild([string]$Encoded) {
  & "$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $Encoded
  return $LASTEXITCODE
}`;

function psVersionCheck(expr: string, rule: { version?: string; operator?: 'eq' | 'gte' | 'lt' }): string {
  if (!rule.version) return '$true';
  const op = rule.operator ?? 'gte';
  const cmp = op === 'eq' ? '-eq 0' : op === 'lt' ? '-lt 0' : '-ge 0';
  return `((Compare-OpenCMVersion ${expr} ${psq(rule.version)}) ${cmp})`;
}

function psRegistryPath(key: string): string {
  const map: Record<string, string> = { HKLM: 'HKEY_LOCAL_MACHINE', HKCU: 'HKEY_CURRENT_USER', HKCR: 'HKEY_CLASSES_ROOT', HKU: 'HKEY_USERS' };
  const [hive, ...rest] = key.split('\\');
  return `Registry::${map[hive!.toUpperCase()] ?? hive!.toUpperCase()}\\${rest.join('\\')}`;
}

function psRule(r: DetectionRule): string {
  switch (r.type) {
    case 'software':
      return `  $apps = @(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and ($_.DisplayName -match ${psq(globToRegex(r.name))}) -and ${psVersionCheck('"$($_.DisplayVersion)"', r)} })
  if ($apps.Count -eq 0) { return $false }`;
    case 'file':
      return `  $p = [Environment]::ExpandEnvironmentVariables(${psq(r.path)})
  if (-not (Test-Path -LiteralPath $p)) { return $false }${
    r.version ? `\n  $fv = (Get-Item -LiteralPath $p).VersionInfo.FileVersion\n  if (-not ${psVersionCheck('"$fv"', { version: r.version, operator: 'gte' })}) { return $false }` : ''
  }`;
    case 'registry': {
      const lines = [`  $k = ${psq(psRegistryPath(r.key))}`, `  if (-not (Test-Path -LiteralPath $k)) { return $false }`];
      if (r.value) {
        lines.push(`  $prop = (Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue).PSObject.Properties[${psq(r.value)}]`, `  if (-not $prop) { return $false }`);
        if (r.data !== undefined && r.data !== '') lines.push(`  if ("$($prop.Value)" -ne ${psq(r.data)}) { return $false }`);
      }
      return lines.join('\n');
    }
    case 'command':
      return `  if ((Invoke-OpenCMChild ${psq(utf16b64(r.command))}) -ne 0) { return $false }`;
  }
}

function psInstall(pkg: PackageInfo, v: PackageVersionInput, action: PackageAction): string {
  const extra = splitArgs(v.installArgs).map(psq).join(' ');
  const needFile = `$file = $env:OPENCM_FILE_1
if (-not $file -or -not (Test-Path -LiteralPath $file)) { Exit-OpenCM 'Installationsdatei fehlt' 2 }`;
  const custom = (cmd: string) => `$code = Invoke-OpenCMChild ${psq(utf16b64(cmd))}`;
  if (action === 'uninstall' && v.uninstallCommand.trim()) return custom(v.uninstallCommand);
  switch (v.type) {
    case 'msi': {
      const log = `$log = Join-Path $env:TEMP ('opencm-msi-' + $env:OPENCM_TASK_ID + '.log')`;
      if (action === 'install') {
        return `${needFile}
${log}
$argList = '/i "' + $file + '" /qn /norestart /l*v "' + $log + '" ' + ${psq(v.installArgs)}
$p = Start-Process -FilePath "$env:SystemRoot\\System32\\msiexec.exe" -ArgumentList $argList -Wait -PassThru -WindowStyle Hidden
$code = $p.ExitCode`;
      }
      const target = v.productCode ? psq(v.productCode) : `('"' + $file + '"')`;
      return `${v.productCode ? '' : `${needFile}\n`}${log}
$argList = '/x ' + ${target} + ' /qn /norestart /l*v "' + $log + '"'
$p = Start-Process -FilePath "$env:SystemRoot\\System32\\msiexec.exe" -ArgumentList $argList -Wait -PassThru -WindowStyle Hidden
$code = $p.ExitCode`;
    }
    case 'exe':
      return `${needFile}
$p = Start-Process -FilePath $file${v.installArgs.trim() ? ` -ArgumentList ${psq(v.installArgs)}` : ''} -Wait -PassThru -WindowStyle Hidden
$code = $p.ExitCode`;
    case 'winget': {
      const verb = action === 'install' ? 'install' : 'uninstall';
      const agreements = action === 'install' ? ' --accept-package-agreements' : '';
      return `# winget is not on PATH for SYSTEM – locate the App Installer binary
$winget = Get-ChildItem "$env:ProgramFiles\\WindowsApps\\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\\winget.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $winget) { Exit-OpenCM 'winget (App Installer) ist nicht installiert' 2 }
& $winget.FullName ${verb} --id ${psq(v.packageRef!)} --exact --silent --disable-interactivity${agreements} --accept-source-agreements --scope machine ${action === 'install' ? extra : ''}
$code = $LASTEXITCODE
# already installed / no applicable upgrade count as success
if ($code -eq -1978335135 -or $code -eq -1978335189) { $code = 0 }`;
    }
    case 'choco':
      return `$choco = Join-Path $env:ProgramData 'chocolatey\\bin\\choco.exe'
if (-not (Test-Path -LiteralPath $choco)) { Exit-OpenCM 'Chocolatey ist nicht installiert' 2 }
& $choco ${action === 'install' ? 'install' : 'uninstall'} ${psq(v.packageRef!)} -y --no-progress --limit-output ${action === 'install' ? extra : ''}
$code = $LASTEXITCODE`;
    case 'script':
      return custom(v.installCommand);
    default:
      throw new Error(`type ${v.type} is not a Windows package type (${pkg.platform})`);
  }
}

function powershellScript(pkg: PackageInfo, version: string, v: PackageVersionInput, action: PackageAction): string {
  const hasRules = v.detection.length > 0;
  const detect = `function Test-OpenCMDetected {
${v.detection.map(psRule).join('\n')}
  return $true
}`;
  const pre =
    action === 'install'
      ? `if (${hasRules ? 'Test-OpenCMDetected' : '$false'}) { Write-Output 'OpenCM: bereits installiert – nichts zu tun'; exit 0 }`
      : `if (${hasRules ? '-not (Test-OpenCMDetected)' : '$false'}) { Write-Output 'OpenCM: nicht installiert – nichts zu tun'; exit 0 }`;
  const post =
    action === 'install'
      ? `if (-not (Test-OpenCMDetected)) { Exit-OpenCM 'Nach der Installation nicht erkannt (Erkennungsregeln prüfen)' 1 }`
      : `if (Test-OpenCMDetected) { Exit-OpenCM 'Nach der Deinstallation weiterhin erkannt' 1 }`;
  return `# OpenCM – ${action === 'install' ? 'Installation' : 'Deinstallation'}: ${oneLine(pkg.name)} ${oneLine(version)} (${v.type}) – automatisch erzeugt
${PS_HEADER}
${detect}
$OpenCMSuccess = @(${v.successCodes.join(', ')})
$OpenCMReboot = @(${v.rebootCodes.join(', ')})
${pre}
Write-Output ${psq(`OpenCM: ${action === 'install' ? 'installiere' : 'deinstalliere'} ${pkg.name} ${version}`)}
${psInstall(pkg, v, action)}
Write-Output "Exitcode: $code"
if ($OpenCMSuccess -notcontains $code -and $OpenCMReboot -notcontains $code) { if ($code -eq 0) { Exit-OpenCM 'Exitcode 0 ist nicht als Erfolg konfiguriert' 1 } else { Exit-OpenCM "Fehlgeschlagen mit Exitcode $code" $code } }
if ($OpenCMReboot -contains $code) { Write-Output 'OPENCM-REBOOT-REQUIRED' }
${hasRules ? `Start-Sleep -Seconds 2\n${post}` : ''}
Write-Output 'OpenCM: erfolgreich'
exit 0
`;
}

// ---------------------------------------------------------------- bash (Linux / macOS)

const SH_HEADER = `set -u
export LC_ALL=C
opencm_fail() { echo "$1" >&2; exit "$2"; }
# opencm_vercmp A B → prints -1 / 0 / 1 (sort -V ordering)
opencm_vercmp() {
  [ "$1" = "$2" ] && { echo 0; return; }
  if [ "$(printf '%s\\n%s\\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]; then echo -1; else echo 1; fi
}
opencm_version_ok() { # installed wanted operator
  [ -z "$2" ] && return 0
  c=$(opencm_vercmp "$1" "$2")
  case "$3" in eq) [ "$c" = 0 ] ;; lt) [ "$c" = -1 ] ;; *) [ "$c" != -1 ] ;; esac
}`;

function shSoftwareRule(platform: Platform, r: Extract<DetectionRule, { type: 'software' }>): string {
  const list =
    platform === 'macos'
      ? `{ for app in /Applications/*.app /Applications/*/*.app; do [ -d "$app" ] || continue; n=$(basename "$app" .app); v=$(defaults read "$app/Contents/Info" CFBundleShortVersionString 2>/dev/null); printf '%s\\t%s\\n' "$n" "$v"; done; for id in $(pkgutil --pkgs 2>/dev/null); do printf '%s\\t%s\\n' "$id" "$(pkgutil --pkg-info "$id" 2>/dev/null | awk '/^version:/{print $2}')"; done; }`
      : `{ dpkg-query -W -f='\${Package}\\t\${Version}\\n' 2>/dev/null; rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null; }`;
  return `  found=1
  while IFS="$(printf '\\t')" read -r n v; do
    [ -n "$n" ] || continue
    if opencm_version_ok "$v" ${shq(r.version ?? '')} ${shq(r.operator ?? 'gte')}; then found=0; break; fi
  done < <(${list} | OPENCM_RE=${shq(globToRegex(r.name))} awk -F'\\t' 'BEGIN { re = tolower(ENVIRON["OPENCM_RE"]) } tolower($1) ~ re { print }')
  [ "$found" = 0 ] || return 1`;
}

function shRule(platform: Platform, r: DetectionRule): string {
  switch (r.type) {
    case 'software':
      return shSoftwareRule(platform, r);
    case 'file':
      return `  [ -e ${shq(r.path)} ] || return 1`;
    case 'command':
      return `  bash -c ${shq(r.command)} >/dev/null 2>&1 || return 1`;
    case 'registry':
      throw new Error('registry rules are Windows-only');
  }
}

function shInstall(v: PackageVersionInput, action: PackageAction): string {
  const extra = splitArgs(v.installArgs).map(shq).join(' ');
  const ref = v.packageRef ? shq(v.packageRef) : '';
  const needFile = `file="\${OPENCM_FILE_1:-}"
[ -n "$file" ] && [ -f "$file" ] || opencm_fail 'Installationsdatei fehlt' 2`;
  const pm = `if command -v dnf >/dev/null 2>&1; then pm=dnf; elif command -v yum >/dev/null 2>&1; then pm=yum; else pm=; fi`;
  if (action === 'uninstall' && v.uninstallCommand.trim()) return `bash -c ${shq(v.uninstallCommand)}\ncode=$?`;
  switch (v.type) {
    case 'apt':
      return action === 'install'
        ? `export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || echo 'apt-get update fehlgeschlagen – fahre fort' >&2
apt-get install -y -q ${extra} -- ${ref}
code=$?`
        : `export DEBIAN_FRONTEND=noninteractive
apt-get remove -y -q -- ${ref}
code=$?`;
    case 'deb':
      return action === 'install'
        ? `${needFile}
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -q ${extra} "$file"
code=$?`
        : `export DEBIAN_FRONTEND=noninteractive
apt-get remove -y -q -- ${ref}
code=$?`;
    case 'dnf':
      return `${pm}
[ -n "$pm" ] || opencm_fail 'Weder dnf noch yum gefunden' 2
"$pm" ${action === 'install' ? `install -y ${extra}` : 'remove -y'} ${ref}
code=$?`;
    case 'rpm':
      return action === 'install'
        ? `${needFile}
${pm}
if [ -n "$pm" ]; then "$pm" install -y ${extra} "$file"; else rpm -Uvh ${extra} "$file"; fi
code=$?`
        : `${pm}
if [ -n "$pm" ]; then "$pm" remove -y ${ref}; else rpm -e ${ref}; fi
code=$?`;
    case 'pkg':
      return `${needFile}
installer -pkg "$file" -target / ${extra}
code=$?`;
    case 'brew':
      return `# Homebrew refuses to run as root: run as the console user
u=$(stat -f%Su /dev/console 2>/dev/null)
[ -n "$u" ] && [ "$u" != root ] || opencm_fail 'Kein angemeldeter Benutzer – Homebrew braucht einen Benutzerkontext' 2
b=
for c in /opt/homebrew/bin/brew /usr/local/bin/brew; do [ -x "$c" ] && b=$c && break; done
[ -n "$b" ] || opencm_fail 'Homebrew ist nicht installiert' 2
sudo -u "$u" -H "$b" ${action === 'install' ? `install ${extra}` : 'uninstall'} ${ref}
code=$?`;
    case 'script':
      return `bash -c ${shq(v.installCommand)}\ncode=$?`;
    default:
      throw new Error(`type ${v.type} is not a Linux/macOS package type`);
  }
}

function bashScript(pkg: PackageInfo, version: string, v: PackageVersionInput, action: PackageAction): string {
  const hasRules = v.detection.length > 0;
  const inList = (codes: number[]) => `case " ${codes.join(' ')} " in *" $code "*) true ;; *) false ;; esac`;
  return `#!/bin/bash
# OpenCM – ${action === 'install' ? 'Installation' : 'Deinstallation'}: ${oneLine(pkg.name)} ${oneLine(version)} (${v.type}) – automatisch erzeugt
${SH_HEADER}
opencm_detected() {
${v.detection.map((r) => shRule(pkg.platform, r)).join('\n')}
  return 0
}
${
  hasRules
    ? action === 'install'
      ? `if opencm_detected; then echo 'OpenCM: bereits installiert – nichts zu tun'; exit 0; fi`
      : `if ! opencm_detected; then echo 'OpenCM: nicht installiert – nichts zu tun'; exit 0; fi`
    : ''
}
echo ${shq(`OpenCM: ${action === 'install' ? 'installiere' : 'deinstalliere'} ${pkg.name} ${version}`)}
${shInstall(v, action)}
echo "Exitcode: $code"
if ! { ${inList(v.successCodes)}; } && ! { ${inList(v.rebootCodes)}; }; then
  [ "$code" = 0 ] && opencm_fail 'Exitcode 0 ist nicht als Erfolg konfiguriert' 1
  opencm_fail "Fehlgeschlagen mit Exitcode $code" "$code"
fi
if { ${inList(v.rebootCodes)}; }; then echo 'OPENCM-REBOOT-REQUIRED'; fi
${
  hasRules
    ? action === 'install'
      ? `opencm_detected || opencm_fail 'Nach der Installation nicht erkannt (Erkennungsregeln prüfen)' 1`
      : `opencm_detected && opencm_fail 'Nach der Deinstallation weiterhin erkannt' 1`
    : ''
}
echo 'OpenCM: erfolgreich'
exit 0
`;
}

const oneLine = (s: string) => s.replace(/[\r\n]+/g, ' ');

// ---------------------------------------------------------------- public API

export const interpreterFor = (platform: Platform) => (platform === 'windows' ? 'powershell' : 'bash');

export function packageScript(pkg: PackageInfo, version: string, v: PackageVersionInput, action: PackageAction): string {
  return pkg.platform === 'windows' ? powershellScript(pkg, version, v, action) : bashScript(pkg, version, v, action);
}

/** Does the step need the installer file on the device? */
export function needsFile(v: PackageVersionInput, action: PackageAction): boolean {
  if (!v.fileSha256) return false;
  if (action === 'install') return true;
  if (v.uninstallCommand.trim()) return v.type === 'script';
  return v.type === 'msi' && !v.productCode;
}

export function packageStep(pkg: PackageInfo, versionId: string, version: string, v: PackageVersionInput, action: PackageAction, position = 0): RunStep {
  const content = packageScript(pkg, version, v, action);
  const files: RunFile[] = needsFile(v, action) ? [{ sha256: v.fileSha256!, name: v.fileName ?? 'installer', sizeBytes: v.fileSize ?? 0 }] : [];
  return {
    position,
    scriptId: '',
    scriptName: `${action === 'install' ? 'Installieren' : 'Deinstallieren'}: ${pkg.name} ${version}`,
    scriptVersionId: '',
    version: 1,
    interpreter: interpreterFor(pkg.platform),
    content,
    sha256: createHash('sha256').update(content).digest('hex'),
    params: {},
    continueOnError: false,
    customFieldId: null,
    kind: 'package',
    packageVersionId: versionId,
    ...(files.length ? { files } : {}),
  };
}
