# OpenCM agent - Windows security posture collector (read-only).
# Embedded into the agent and run via powershell.exe -EncodedCommand as a second script
# (the inventory script is close to the command line length limit).
# Output: one JSON object matching SecuritySchema (server/src/inventory/schema.ts).
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Iso($d) {
  if ($null -eq $d -or $d -eq '') { return $null }
  try { $t = [datetime]$d; if ($t.Year -lt 1990) { return $null }; return $t.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { return $null }
}
function Str($v) { if ($null -eq $v) { return $null } $s = "$v".Trim(); if ($s -eq '') { return $null } return $s }

# --- BitLocker / device encryption (Win32_EncryptableVolume works without the BitLocker module)
$methods = @{ 0 = 'None'; 1 = 'AES128Diffuser'; 2 = 'AES256Diffuser'; 3 = 'AES128'; 4 = 'AES256'; 5 = 'Hardware'; 6 = 'XtsAes128'; 7 = 'XtsAes256' }
$conversion = @{ 0 = 'FullyDecrypted'; 1 = 'FullyEncrypted'; 2 = 'EncryptionInProgress'; 3 = 'DecryptionInProgress'; 4 = 'EncryptionPaused'; 5 = 'DecryptionPaused' }
$volumes = @()
$encVols = @(Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume)
foreach ($v in $encVols) {
  # VolumeType: 0 = OS volume, 1 = fixed data volume, 2 = removable
  if ($null -ne $v.VolumeType -and [int]$v.VolumeType -gt 1) { continue }
  if (-not $v.DriveLetter) { continue }
  $conv = Invoke-CimMethod -InputObject $v -MethodName GetConversionStatus
  $cs = if ($conv) { [int]$conv.ConversionStatus } else { -1 }
  $em = Invoke-CimMethod -InputObject $v -MethodName GetEncryptionMethod
  $prot = $null
  if ($null -ne $v.ProtectionStatus -and [int]$v.ProtectionStatus -ne 2) { $prot = ([int]$v.ProtectionStatus -eq 1) }
  $encrypted = $null
  if ($cs -ge 0) { $encrypted = ($cs -eq 1) }
  $volumes += [ordered]@{
    volume     = "$($v.DriveLetter)"
    system     = ("$($v.DriveLetter)" -eq "$env:SystemDrive") -or ($v.VolumeType -eq 0)
    encrypted  = $encrypted
    status     = if ($conversion.ContainsKey($cs)) { $conversion[$cs] } else { $null }
    method     = if ($em -and $methods.ContainsKey([int]$em.EncryptionMethod)) { $methods[[int]$em.EncryptionMethod] } else { $null }
    protection = $prot
  }
}
$encryption = [ordered]@{ product = if ($encVols.Count) { 'BitLocker' } else { $null }; volumes = @($volumes) }

# --- antivirus: Microsoft Defender + third-party products registered in the Security Center (clients)
$av = @()
$mp = Get-MpComputerStatus
if ($mp) {
  $scans = @($mp.QuickScanEndTime, $mp.FullScanEndTime) | Where-Object { $_ } | Sort-Object -Descending
  $passive = "$($mp.AMRunningMode)" -match 'Passive|EDR'
  $av += [ordered]@{
    name               = 'Microsoft Defender Antivirus'
    enabled            = ([bool]$mp.AntivirusEnabled -and -not $passive)
    realtime           = [bool]$mp.RealTimeProtectionEnabled
    upToDate           = $null
    signatureVersion   = Str $mp.AntivirusSignatureVersion
    signatureUpdatedAt = Iso $mp.AntivirusSignatureLastUpdated
    lastScanAt         = Iso ($scans | Select-Object -First 1)
  }
}
foreach ($p in @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct)) {
  if ("$($p.displayName)" -match 'Windows Defender|Microsoft Defender') { continue }
  # productState: byte 2 = scanner state (0x10/0x11 = on), byte 3 = signatures (0x00 = up to date)
  $hex = '{0:X6}' -f [int]$p.productState
  $av += [ordered]@{
    name               = "$($p.displayName)"
    enabled            = @('10', '11') -contains $hex.Substring(2, 2)
    realtime           = $null
    upToDate           = ($hex.Substring(4, 2) -eq '00')
    signatureVersion   = $null
    signatureUpdatedAt = $null
    lastScanAt         = $null
  }
}

# --- firewall profiles
$profiles = @(Get-NetFirewallProfile | ForEach-Object {
  [ordered]@{ name = "$($_.Name)"; enabled = ("$($_.Enabled)" -eq 'True' -or "$($_.Enabled)" -eq '1') }
})
$firewall = [ordered]@{ product = 'Windows Defender Firewall'; enabled = $null; profiles = $profiles }

# --- Secure Boot (UEFI) and TPM
$secureBoot = $null
try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch {
  $reg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
  if ($reg -and $null -ne $reg.UEFISecureBootEnabled) { $secureBoot = ([int]$reg.UEFISecureBootEnabled -eq 1) }
}
$tpm = [ordered]@{ present = $null; ready = $null; version = $null }
$t = Get-Tpm
if ($t) { $tpm.present = [bool]$t.TpmPresent; $tpm.ready = [bool]$t.TpmReady }
$wt = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftTpm' -ClassName Win32_Tpm
if ($wt -and $wt.SpecVersion) { $tpm.version = ("$($wt.SpecVersion)".Split(',')[0]).Trim(); if ($null -eq $tpm.present) { $tpm.present = $true } }

[ordered]@{
  encryption = $encryption
  antivirus  = @($av)
  firewall   = $firewall
  secureBoot = $secureBoot
  tpm        = $tpm
} | ConvertTo-Json -Depth 6 -Compress
