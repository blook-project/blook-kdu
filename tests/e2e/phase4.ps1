# Phase 4: repeated load / read stress through the usable drivers.
param([string] $BundleDir = 'C:\kdu-e2e', [string] $OutDir = 'C:\kdu-e2e\out')
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
New-Item -ItemType Directory -Force $OutDir | Out-Null
$kdu = Join-Path $BundleDir 'kdu.exe'
$results = New-Object System.Collections.Generic.List[object]
function Add-Result([string] $name, [bool] $ok, [string] $detail) {
    $results.Add([pscustomobject]@{ name = $name; ok = $ok; detail = $detail })
    Write-Host ("[{0}] {1}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name)
}
function Add-Skip([string] $name, [string] $reason) {
    $results.Add([pscustomobject]@{ name = $name; ok = $true; skipped = $true; detail = ("SKIP: " + $reason) })
    Write-Host ("[SKIP] {0}: {1}" -f $name, $reason)
}
function Invoke-Kdu([string[]] $arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if (-not ($arguments -contains '--no-payload')) { $arguments = @('--no-payload') + $arguments }
        $output = & $kdu @arguments 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    return @{ code = $code; output = $output }
}

$modules = Invoke-Kdu @('--json', 'modules')
$ntos = $null
try { $ntos = ($modules.output | ConvertFrom-Json) | Where-Object { $_.name -eq 'ntoskrnl.exe' } | Select-Object -First 1 } catch { }
if ($ntos) {
    $failures = 0
    for ($index = 0; $index -lt 5; $index++) {
        $run = Invoke-Kdu @('--exploit', 'rtcore64', '--driver-only', '--json', 'mem', 'virt', 'read', $ntos.base, '8')
        if ($run.code -ne 0) { $failures++ }
    }
    Add-Result 'stress/load-unload' ($failures -eq 0) ("5x, failures=" + $failures)
} else {
    Add-Skip 'stress/load-unload' 'kernel module list unavailable'
}

$readFailures = 0
for ($index = 0; $index -lt 20; $index++) {
    $run = Invoke-Kdu @('--exploit', 'winring0', '--driver-only', '--json', 'mem', 'phys', 'read', '0x1000', '16')
    if ($run.code -ne 0) { $readFailures++ }
}
Add-Result 'stress/read' ($readFailures -eq 0) ("20x, failures=" + $readFailures)

$failed = @($results | Where-Object { -not $_.ok }).Count
$document = [ordered]@{ suite = 'blook-kdu-e2e'; phase = 4; total = $results.Count
    failed = $failed; results = $results }
$document | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir 'result-4.json') -Encoding UTF8
if ($failed -ne 0) { exit 1 }
