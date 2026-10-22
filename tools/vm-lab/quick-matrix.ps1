# blook-kdu: minimal serialized VM test runner (Lead's fix-iteration lane).
#
# Unlike scripts/vm-lab.ps1 (full matrix, signing, prepare, crash handling) this
# runner assumes the guest is already prepared and the signed drivers are staged
# in C:\byovd\drivers, and simply runs `kdu exploits test <id>` per id through
# bvmenv, recording PASS/FAIL/timeout. Intended for small fix batches.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]] $Ids,
    [string] $Vm = 'vm-byovd',
    [string] $Out = '',
    [int] $TimeoutSeconds = 90,
    [string] $Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string] $Bvmenv = 'D:\blook-kernel-project\blook-vmware-environment\build\windows\x64\release\bvmenv.exe'
)
$ErrorActionPreference = 'Stop'
$Ids = @($Ids | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { $_ })
if (-not $Out) { $Out = Join-Path $Root ("docs/lab/quick-{0}" -f (Get-Date -Format 'HHmmss')) }
New-Item -ItemType Directory -Force $Out | Out-Null
New-Item -ItemType Directory -Force (Join-Path $Out 'raw') | Out-Null
$logPath = Join-Path $Out 'quick.log'
function Log([string] $m) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
    Write-Host $line
    Add-Content -LiteralPath $logPath -Value $line -Encoding utf8
}
$mutex = New-Object System.Threading.Mutex($false, 'Global\blook-kdu-vmlab')
try {
    try { $owned = $mutex.WaitOne([TimeSpan]::FromSeconds(3600)) } catch [System.Threading.AbandonedMutexException] { $owned = $true; Write-Host 'recovered abandoned vm-lab mutex' }
} catch [System.Threading.AbandonedMutexException] {
    $owned = $true
}
if (-not $owned) { throw 'vm lab mutex timeout' }
try {
    $rows = @()
    foreach ($id in $Ids) {
        $text = (& $Bvmenv exec $Vm --elevated --timeout $TimeoutSeconds -- "cmd /c C:\byovd\run-test.cmd $id" 2>&1 | Out-String)
        $status = 'FAIL'
        if ($text -match 'PASS\s+\S+.*ntoskrnl=') { $status = 'PASS' }
        elseif ($text -match 'SKIP\s+\S+') { $status = 'SKIP' }
        elseif ($text -match 'guest script failed \(timeout\)|not powered on|VMware Tools are not running') { $status = 'CRASH' }
        Set-Content -LiteralPath (Join-Path $Out "raw/$id.log") -Value $text -Encoding utf8
        $detail = [string]((($text -split "`n") | Where-Object { $_ -match 'PASS|FAIL|SKIP|error' } | Select-Object -First 1)); $detail = $detail.Trim()
        Log ("{0} {1} {2}" -f $status, $id, $detail)
        $rows += [pscustomobject]@{ id = $id; status = $status; detail = $detail; raw = "raw/$id.log" }
        if ($status -eq 'CRASH') {
            Log 'guest crashed/hung; resetting and re-preparing'
            & $Bvmenv reset $Vm | Out-Null
            & $Bvmenv start $Vm | Out-Null
            & $Bvmenv wait-ready $Vm --timeout 420 | Out-Null
            & $Bvmenv exec $Vm --elevated --timeout 180 -- 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\byovd\guest-prepare.ps1 -ByovdDir C:\byovd -TestSigning' | Out-Null
            & $Bvmenv push $Vm (Join-Path $Root 'build/windows/x64/release/kdu.exe') 'C:\byovd\kdu.exe' | Out-Null
            New-Item -ItemType Directory -Force (Join-Path $Root 'build/generated/signed-drivers') | Out-Null
            & $Bvmenv push $Vm (Join-Path $Root 'build/generated/signed-drivers') 'C:\byovd\drivers' | Out-Null
            & $Bvmenv push $Vm (Join-Path $Root 'build/generated/certs') 'C:\byovd\certs' | Out-Null
            & $Bvmenv exec $Vm --elevated --timeout 180 -- 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\byovd\guest-prepare.ps1 -ByovdDir C:\byovd -TestSigning' | Out-Null
        }
    }
    $rows | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Out 'quick-matrix.json') -Encoding utf8
    $pass = @($rows | Where-Object { $_.status -eq 'PASS' }).Count
    Log ("done: {0} ids, {1} PASS -> {2}" -f $rows.Count, $pass, $Out)
} finally {
    if ($owned) { [void]$mutex.ReleaseMutex() }
    $mutex.Dispose()
}
