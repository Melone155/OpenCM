/**
 * Built-in patch scan / install steps. Output protocol (all platforms), parsed by ingest.ts:
 *
 *   -----OPENCM-PATCHES-BEGIN-----
 *   S<TAB>source                 windows_update | apt | dnf | softwareupdate
 *   R<TAB>0|1                    reboot pending
 *   U<TAB>id<TAB>title<TAB>kb<TAB>classification<TAB>severity<TAB>security 0|1<TAB>version<TAB>reboot 0|1
 *   -----OPENCM-PATCHES-END-----
 */
import { createHash } from 'node:crypto';
import type { PatchFilter, RunStep } from '../db/schema.ts';
import { psq, shq } from '../packages/generate.ts';

export const PATCH_BEGIN = '-----OPENCM-PATCHES-BEGIN-----';
export const PATCH_END = '-----OPENCM-PATCHES-END-----';

export type PatchOs = 'windows' | 'linux' | 'macos';

// Classification GUIDs are language independent (names are localised on non-English Windows).
const PS_WUA = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Clean([object]$s) { if ($null -eq $s) { return '' } return (([string]$s) -replace '[\\t\\r\\n]+', ' ').Trim() }
$OpenCMClass = @{
  '0fa1201d-4330-4fa8-8ae9-b877473b6441' = 'Security Updates'; 'e6cf1350-c01b-414d-a61f-263d14d133b4' = 'Critical Updates'
  'e0789628-ce08-4437-be74-2495b842f43b' = 'Definition Updates'; '28bc880e-0592-4cbf-8f95-c79b17911d5f' = 'Update Rollups'
  'cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83' = 'Updates'; 'b54e7d24-7add-428f-8b75-90a396fa584f' = 'Feature Packs'
  '68c5b0a3-d1a6-4553-ae49-01d3a7827828' = 'Service Packs'; '3689bdc8-b205-4af4-8d4a-a63924c5e9d5' = 'Upgrades'
  'ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0' = 'Drivers'; 'b4832bd8-e735-4761-8daf-37f882276dab' = 'Tools'
}
function Get-OpenCMClass($u) {
  foreach ($c in $u.Categories) { if ($c.Type -eq 'UpdateClassification') { $n = $OpenCMClass[([string]$c.CategoryID).ToLower()]; if ($n) { return $n } return (Clean $c.Name) } }
  return ''
}
function Test-OpenCMSecurity($u, [string]$cls) { return ($cls -eq 'Security Updates' -or $cls -eq 'Critical Updates' -or -not [string]::IsNullOrEmpty($u.MsrcSeverity)) }
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $session.ClientApplicationID = 'OpenCM'
  $result = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
} catch { [Console]::Error.WriteLine("Windows-Update-Suche fehlgeschlagen: $($_.Exception.Message)"); exit 3 }`;

const PS_SCAN = `${PS_WUA}
$reboot = 0
try { if ((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired) { $reboot = 1 } } catch {}
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("S\`twindows_update"); $lines.Add("R\`t$reboot")
foreach ($u in $result.Updates) {
  $cls = Get-OpenCMClass $u
  $kb = (@($u.KBArticleIDs) | ForEach-Object { "KB$_" }) -join ','
  $sec = if (Test-OpenCMSecurity $u $cls) { 1 } else { 0 }
  $rb = if ($u.InstallationBehavior.RebootBehavior -ne 0) { 1 } else { 0 }
  $lines.Add("U\`t$($u.Identity.UpdateID)\`t$(Clean $u.Title)\`t$kb\`t$cls\`t$(Clean $u.MsrcSeverity)\`t$sec\`t\`t$rb")
}
Write-Output '${PATCH_BEGIN}'
foreach ($l in $lines) { Write-Output $l }
Write-Output '${PATCH_END}'
Write-Output "$($result.Updates.Count) Update(s) ausstehend"
exit 0
`;

function psInstall(f: PatchFilter): string {
  return `${PS_WUA}
$include = @(${f.include.map(psq).join(', ')})
$mode = ${psq(f.classification)}
$coll = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $result.Updates) {
  $cls = Get-OpenCMClass $u
  $kbs = @($u.KBArticleIDs | ForEach-Object { "KB$_" })
  if ($include.Count -gt 0) { $ok = ($include -contains $u.Identity.UpdateID) -or (@($kbs | Where-Object { $include -contains $_ }).Count -gt 0) }
  elseif ($mode -eq 'critical') { $ok = ($cls -eq 'Critical Updates') -or ($u.MsrcSeverity -eq 'Critical') }
  elseif ($mode -eq 'security') { $ok = Test-OpenCMSecurity $u $cls }
  else { $ok = ($cls -ne 'Upgrades' -and $cls -ne 'Drivers') }
  if ($ok) { if (-not $u.EulaAccepted) { $u.AcceptEula() }; [void]$coll.Add($u) }
}
if ($coll.Count -eq 0) { Write-Output 'Keine passenden Updates ausstehend.'; exit 0 }
Write-Output "Lade $($coll.Count) Update(s) herunter …"
$dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll; [void]$dl.Download()
$inst = $session.CreateUpdateInstaller(); $inst.Updates = $coll
Write-Output 'Installiere …'
$r = $inst.Install()
$names = @{ 0 = 'nicht gestartet'; 1 = 'läuft'; 2 = 'erfolgreich'; 3 = 'mit Fehlern'; 4 = 'fehlgeschlagen'; 5 = 'abgebrochen' }
for ($i = 0; $i -lt $coll.Count; $i++) { Write-Output ("{0}: {1}" -f $coll.Item($i).Title, $names[[int]$r.GetUpdateResult($i).ResultCode]) }
if ($r.RebootRequired) {
  Write-Output 'OPENCM-REBOOT-REQUIRED'
  ${f.reboot === 'if_required' ? `& "$env:SystemRoot\\System32\\shutdown.exe" /r /t 300 /c 'OpenCM: Neustart nach Updates in 5 Minuten'
  Write-Output 'Neustart in 5 Minuten geplant.'` : `Write-Output 'Neustart erforderlich (wird nicht automatisch ausgelöst).'`}
}
if ([int]$r.ResultCode -eq 2 -or [int]$r.ResultCode -eq 3) { exit 0 }
[Console]::Error.WriteLine("Installation fehlgeschlagen (ResultCode $([int]$r.ResultCode), HResult $($r.HResult))")
exit 1
`;
}

const SH_COMMON = `set -u
export LC_ALL=C
opencm_fail() { echo "$1" >&2; exit "$2"; }`;

const LINUX_SCAN = `#!/bin/bash
${SH_COMMON}
reboot=0
tmp=$(mktemp -d) || opencm_fail 'mktemp fehlgeschlagen' 1
trap 'rm -rf "$tmp"' EXIT
if command -v apt-get >/dev/null 2>&1; then
  src=apt
  [ -f /var/run/reboot-required ] && reboot=1
  apt-get update -qq >/dev/null 2>&1 || echo 'apt-get update fehlgeschlagen – verwende vorhandene Paketlisten' >&2
  apt list --upgradable 2>/dev/null | awk '
    / upgradable from/ {
      split($1, a, "/"); name = a[1]; suites = a[2]; ver = $2
      sec = (suites ~ /-security/) ? 1 : 0
      rb = (name ~ /^linux-image/) ? 1 : 0
      printf "U\\t%s\\t%s %s\\t\\t%s\\t\\t%d\\t%s\\t%d\\n", name, name, ver, (sec ? "security" : "updates"), sec, ver, rb
    }' > "$tmp/u"
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  src=dnf
  pm=$(command -v dnf || command -v yum)
  if command -v needs-restarting >/dev/null 2>&1; then needs-restarting -r >/dev/null 2>&1 || reboot=1; fi
  "$pm" -q updateinfo list --updates --security 2>/dev/null > "$tmp/sec" || true
  "$pm" -q check-update 2>/dev/null > "$tmp/upd"
  rc=$?
  [ "$rc" = 1 ] && opencm_fail "$pm check-update fehlgeschlagen" 3
  awk '
    NR == FNR { if (NF >= 3) { n = $3; sub(/\\.[^.]+$/, "", n); sub(/-[^-]+-[^-]+$/, "", n); sev[n] = $2; adv[n] = $1 } next }
    NF == 3 && $1 ~ /\\./ && $2 ~ /[0-9]/ {
      name = $1; sub(/\\.[^.]+$/, "", name)
      s = (name in sev) ? 1 : 0; sv = s ? sev[name] : ""; sub(/\\/Sec\\.$/, "", sv)
      rb = (name ~ /^kernel/) ? 1 : 0
      printf "U\\t%s\\t%s %s\\t%s\\t%s\\t%s\\t%d\\t%s\\t%d\\n", name, name, $2, (s ? adv[name] : ""), (s ? "security" : "updates"), sv, s, $2, rb
    }' "$tmp/sec" "$tmp/upd" > "$tmp/u"
else
  opencm_fail 'Kein unterstützter Paketmanager (apt, dnf, yum) gefunden' 3
fi
echo '${PATCH_BEGIN}'
printf 'S\\t%s\\nR\\t%s\\n' "$src" "$reboot"
cat "$tmp/u"
echo '${PATCH_END}'
echo "$(wc -l < "$tmp/u" | tr -d ' ') Update(s) ausstehend"
exit 0
`;

const MAC_SCAN = `#!/bin/bash
${SH_COMMON}
out=$(softwareupdate -l 2>&1)
rc=$?
[ "$rc" = 0 ] || opencm_fail "softwareupdate -l fehlgeschlagen: $out" 3
echo '${PATCH_BEGIN}'
printf 'S\\tsoftwareupdate\\nR\\t0\\n'
printf '%s\\n' "$out" | awk '
  /^\\* Label: / { label = substr($0, index($0, ":") + 2); next }
  /Title: / && label != "" {
    t = $0; sub(/^[ \\t]*Title: /, "", t)
    title = t; sub(/, Version:.*/, "", title)
    ver = ""; if (match(t, /Version: [^,]+/)) ver = substr(t, RSTART + 9, RLENGTH - 9)
    rec = (t ~ /Recommended: YES/) ? 1 : 0
    rb = (t ~ /Action: restart/) ? 1 : 0
    printf "U\\t%s\\t%s\\t\\t%s\\t\\t%d\\t%s\\t%d\\n", label, title, (rec ? "recommended" : "optional"), rec, ver, rb
    label = ""
  }'
echo '${PATCH_END}'
exit 0
`;

function linuxInstall(f: PatchFilter): string {
  const include = f.include.map(shq).join(' ');
  return `#!/bin/bash
${SH_COMMON}
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  opts="-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
  apt-get update -qq || echo 'apt-get update fehlgeschlagen' >&2
  ${
    f.include.length
      ? `apt-get install --only-upgrade $opts -- ${include}`
      : f.classification === 'all'
        ? `apt-get upgrade $opts`
        : `pkgs=$(apt list --upgradable 2>/dev/null | awk -F/ '/-security/ { print $1 }')
  [ -n "$pkgs" ] || { echo 'Keine Sicherheitsupdates ausstehend.'; exit 0; }
  # shellcheck disable=SC2086
  apt-get install --only-upgrade $opts $pkgs`
  }
  code=$?
  [ -f /var/run/reboot-required ] && needreboot=1 || needreboot=0
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  pm=$(command -v dnf || command -v yum)
  ${
    f.include.length
      ? `"$pm" upgrade -y ${include}`
      : f.classification === 'all'
        ? `"$pm" upgrade -y`
        : f.classification === 'critical'
          ? `"$pm" upgrade -y --security --sec-severity=Critical`
          : `"$pm" upgrade -y --security`
  }
  code=$?
  needreboot=0
  if command -v needs-restarting >/dev/null 2>&1; then needs-restarting -r >/dev/null 2>&1 || needreboot=1; fi
else
  opencm_fail 'Kein unterstützter Paketmanager (apt, dnf, yum) gefunden' 3
fi
if [ "$needreboot" = 1 ]; then
  echo 'OPENCM-REBOOT-REQUIRED'
  ${f.reboot === 'if_required' ? `shutdown -r +5 'OpenCM: Neustart nach Updates in 5 Minuten' && echo 'Neustart in 5 Minuten geplant.'` : `echo 'Neustart erforderlich (wird nicht automatisch ausgelöst).'`}
fi
exit "$code"
`;
}

function macInstall(f: PatchFilter): string {
  const what = f.include.length ? f.include.map(shq).join(' ') : f.classification === 'all' ? '-a' : '-r';
  return `#!/bin/bash
${SH_COMMON}
# Hinweis: Betriebssystem-Updates auf Apple-Silicon-Macs können eine Benutzerbestätigung erfordern.
softwareupdate -i ${what} ${f.reboot === 'if_required' ? '-R' : ''} --agree-to-license 2>&1
code=$?
exit "$code"
`;
}

const scanContent: Record<PatchOs, string> = { windows: PS_SCAN, linux: LINUX_SCAN, macos: MAC_SCAN };

function step(kind: 'patch_scan' | 'patch_install', name: string, os: PatchOs, content: string, position: number): RunStep {
  return {
    position,
    scriptId: '',
    scriptName: name,
    scriptVersionId: '',
    version: 1,
    interpreter: os === 'windows' ? 'powershell' : 'bash',
    content,
    sha256: createHash('sha256').update(content).digest('hex'),
    params: {},
    continueOnError: false,
    customFieldId: null,
    kind,
  };
}

export function patchScanStep(os: PatchOs, position = 0): RunStep {
  return step('patch_scan', 'Patch-Scan', os, scanContent[os], position);
}

/** Install step followed by a scan, so the patch state is current afterwards. */
export function patchInstallSteps(os: PatchOs, f: PatchFilter): RunStep[] {
  const content = os === 'windows' ? psInstall(f) : os === 'linux' ? linuxInstall(f) : macInstall(f);
  const label = f.include.length ? `${f.include.length} ausgewählte` : f.classification === 'all' ? 'alle' : f.classification === 'critical' ? 'kritische' : 'Sicherheits-';
  return [step('patch_install', `Updates installieren (${label})`, os, content, 0), patchScanStep(os, 1)];
}

export const PATCH_OSES: PatchOs[] = ['windows', 'linux', 'macos'];
