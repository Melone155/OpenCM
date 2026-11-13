# OpenCM agent – Windows inventory collector.
# Embedded into the agent binary and run via powershell.exe -EncodedCommand.
# Output: one JSON object on stdout (UTF-8) matching the server's inventory schema
# (network and collectedAt are added by the Go side). Read-only; requires PowerShell 5.1+.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Iso($d) {
  if ($null -eq $d -or $d -eq '') { return $null }
  try { return ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { return $null }
}
function Str($v) { if ($null -eq $v) { return $null } $s = "$v".Trim(); if ($s -eq '') { return $null } return $s }

$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$os   = Get-CimInstance Win32_OperatingSystem
$cpus = @(Get-CimInstance Win32_Processor)
$encl = Get-CimInstance Win32_SystemEnclosure

$chassisNames = @{ 3='Desktop'; 4='Low Profile Desktop'; 6='Mini Tower'; 7='Tower'; 8='Portable'; 9='Laptop'; 10='Notebook';
  13='All in One'; 14='Sub Notebook'; 17='Main Server Chassis'; 23='Rack Mount Chassis'; 30='Tablet'; 31='Convertible'; 32='Detachable'; 35='Mini PC' }
$chassis = $null
if ($encl -and $encl.ChassisTypes) { $t = [int]$encl.ChassisTypes[0]; $chassis = if ($chassisNames.ContainsKey($t)) { $chassisNames[$t] } else { "Type $t" } }
if ($cs.Model -match 'Virtual|VMware|KVM|HVM domU|VirtualBox') { $chassis = 'Virtual Machine' }

$cores = 0; $logical = 0
foreach ($c in $cpus) { $cores += [int]$c.NumberOfCores; $logical += [int]$c.NumberOfLogicalProcessors }

$hardware = [ordered]@{
  manufacturer = Str $cs.Manufacturer
  model        = Str $cs.Model
  serialNumber = Str $bios.SerialNumber
  chassis      = $chassis
  biosVendor   = Str $bios.Manufacturer
  biosVersion  = Str $bios.SMBIOSBIOSVersion
  biosDate     = Iso $bios.ReleaseDate
  cpu          = [ordered]@{
    model             = Str ($cpus | Select-Object -First 1).Name
    cores             = $cores
    logicalProcessors = $logical
    mhz               = [int]($cpus | Select-Object -First 1).MaxClockSpeed
  }
  memoryBytes  = [double]$cs.TotalPhysicalMemory
}

$osInfo = [ordered]@{
  name        = Str $os.Caption
  version     = Str $os.Version
  build       = Str $os.BuildNumber
  arch        = Str $os.OSArchitecture
  kernel      = Str $os.Version
  installDate = Iso $os.InstallDate
  lastBoot    = Iso $os.LastBootUpTime
}
$ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
if ($ubr) { $osInfo.build = "$($os.BuildNumber).$ubr" }
$displayVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
if ($displayVersion) { $osInfo.version = "$displayVersion ($($os.Version))" }

# --- disks (local fixed volumes)
$disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
  [ordered]@{ name = $_.DeviceID; mount = "$($_.DeviceID)\"; fsType = Str $_.FileSystem; sizeBytes = [double]$_.Size; freeBytes = [double]$_.FreeSpace }
})

# --- installed software (machine-wide uninstall keys, 64- and 32-bit views)
$software = New-Object System.Collections.ArrayList
$seen = @{}
$keys = @(
  @{ path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' } },
  @{ path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; arch = 'x86' }
)
foreach ($k in $keys) {
  foreach ($p in @(Get-ItemProperty $k.path)) {
    $name = Str $p.DisplayName
    if (-not $name) { continue }
    if ($p.SystemComponent -eq 1 -or $p.ParentKeyName -or $p.ReleaseType -in @('Update', 'Hotfix', 'Security Update')) { continue }
    $ver = "$($p.DisplayVersion)".Trim()
    $key = "$name|$ver|$($k.arch)"
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $date = $null
    if ("$($p.InstallDate)" -match '^(\d{4})(\d{2})(\d{2})$') { $date = "$($Matches[1])-$($Matches[2])-$($Matches[3])" }
    [void]$software.Add([ordered]@{
      name = $name; version = $ver; publisher = "$($p.Publisher)".Trim(); installDate = $date
      source = if ($p.WindowsInstaller -eq 1) { 'msi' } else { 'registry' }; arch = $k.arch
    })
  }
}
# Store/MSIX apps for all users (best effort; requires admin)
foreach ($a in @(Get-AppxPackage -AllUsers | Where-Object { -not $_.IsFramework -and $_.SignatureKind -ne 'System' })) {
  $key = "$($a.Name)|$($a.Version)|appx"
  if ($seen.ContainsKey($key)) { continue }
  $seen[$key] = $true
  $pub = if ($a.Publisher -match 'CN=([^,]+)') { $Matches[1] } else { "$($a.Publisher)" }
  [void]$software.Add([ordered]@{ name = $a.Name; version = "$($a.Version)"; publisher = $pub; installDate = $null; source = 'appx'; arch = "$($a.Architecture)".ToLower() })
}

# --- patches
$patches = @(Get-CimInstance Win32_QuickFixEngineering | ForEach-Object {
  $on = $null
  if ($_.InstalledOn) { $on = Iso $_.InstalledOn }
  [ordered]@{ id = $_.HotFixID; description = Str $_.Description; installedOn = $on }
})

# --- services
$services = @(Get-CimInstance Win32_Service | ForEach-Object {
  [ordered]@{ name = $_.Name; displayName = Str $_.DisplayName; state = Str $_.State; startMode = Str $_.StartMode }
})

# --- autostart
$autostart = @(Get-CimInstance Win32_StartupCommand | ForEach-Object {
  [ordered]@{ name = $_.Name; command = Str $_.Command; location = Str $_.Location }
})

# --- local users and groups
$localUsers = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | ForEach-Object {
  [ordered]@{ name = $_.Name; fullName = Str $_.FullName; disabled = [bool]$_.Disabled; uid = $_.SID }
})
# Group members via the ADSI WinNT provider: ~100x faster than the CIM association
# Win32_GroupUser on domain-joined machines (measured: 0.2 s vs. 47 s).
$localGroups = @()
try {
  $computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
  $localGroups = @($computer.psbase.Children | Where-Object { $_.SchemaClassName -eq 'group' } | ForEach-Object {
    $members = @(@($_.psbase.Invoke('Members')) | ForEach-Object {
      $path = $_.GetType().InvokeMember('AdsPath', 'GetProperty', $null, $_, $null)
      # WinNT://DOMAIN/user or WinNT://DOMAIN/COMPUTER/user → DOMAIN\user / COMPUTER\user
      $parts = "$path".Substring(8).Split('/')
      if ($parts.Count -ge 2) { "$($parts[$parts.Count - 2])\$($parts[$parts.Count - 1])" } else { "$path" }
    })
    [ordered]@{ name = "$($_.Name)"; members = $members }
  })
} catch {
  $localGroups = @(Get-CimInstance Win32_Group -Filter 'LocalAccount=True' | ForEach-Object { [ordered]@{ name = $_.Name; members = @() } })
}

# --- interactively logged-on users (explorer.exe owners covers console + RDP sessions)
$logged = @{}
foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'")) {
  $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner
  if ($o -and $o.User) { $logged["$($o.Domain)\$($o.User)"] = $true }
}
if ($cs.UserName) { $logged["$($cs.UserName)"] = $true }

$result = [ordered]@{
  hardware      = $hardware
  os            = $osInfo
  disks         = $disks
  software      = @($software)
  patches       = $patches
  services      = $services
  autostart     = $autostart
  localUsers    = $localUsers
  localGroups   = $localGroups
  loggedOnUsers = @($logged.Keys)
}
$result | ConvertTo-Json -Depth 6 -Compress
