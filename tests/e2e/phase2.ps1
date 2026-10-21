# Phase 2: kernel reads through the drivers usable on this build.
param([string] $BundleDir = 'C:\kdu-e2e', [string] $OutDir = 'C:\kdu-e2e\out')
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
New-Item -ItemType Directory -Force $OutDir | Out-Null
$kdu = Join-Path $BundleDir 'kdu.exe'
$results = New-Object System.Collections.Generic.List[object]
function Add-Result([string] $name, [bool] $ok, [string] $detail) {
    $results.Add([pscustomobject]@{ name = $name; ok = $ok; detail = $detail })
    Add-Content -Path (Join-Path $OutDir 'progress.log') -Value ("[" + $(if ($ok) { 'PASS' } else { 'FAIL' }) + "] $name") -ErrorAction SilentlyContinue
    Write-Host ("[{0}] {1}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name)
}
function Add-Skip([string] $name, [string] $reason) {
    $results.Add([pscustomobject]@{ name = $name; ok = $true; skipped = $true; detail = ("SKIP: " + $reason) })
    Add-Content -Path (Join-Path $OutDir 'progress.log') -Value ("[SKIP] $name") -ErrorAction SilentlyContinue
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
Add-Result 'memory/modules' ($modules.code -eq 0) 'kernel module list'
$ntos = $null
try { $ntos = ($modules.output | ConvertFrom-Json) | Where-Object { $_.name -eq 'ntoskrnl.exe' } | Select-Object -First 1 } catch { }
if ($ntos) {
    $virtual = Invoke-Kdu @('--exploit', 'rtcore64', '--driver-only', '--json', 'mem', 'virt', 'read', $ntos.base, '16')
    $hex = ''
    try { $hex = ($virtual.output | ConvertFrom-Json).hex } catch { }
    Add-Result 'memory/virtual-read' ($virtual.code -eq 0 -and $hex -like '4d5a*') ("hex=" + $hex)
} else {
    Add-Skip 'memory/virtual-read' 'ntoskrnl not in module list'
}
$physical = Invoke-Kdu @('--exploit', 'winring0', '--driver-only', '--json', 'mem', 'phys', 'read', '0x1000', '16')
$hex = ''
try { $hex = ($physical.output | ConvertFrom-Json).hex } catch { }
Add-Result 'memory/physical-read' ($physical.code -eq 0 -and $hex.Length -ge 16) ("hex=" + $hex)
$guard = Invoke-Kdu @('--exploit', 'winring0', '--driver-only', '--json', 'mem', 'virt', 'read', '0xFFFFF80000000000', '8')
Add-Result 'safety/winring0-va-guard' ($guard.code -ne 0) 'page walk refused'
Add-Skip 'memory/process-read' 'CR3 walk needs a safe physical-read driver; only WinRing0 is usable and its page walk is unsafe by design'
Add-Skip 'memory/process-write' 'same as process-read'
Add-Skip 'payload/map' 'manual-map payload cannot execute on this build (kernel executable memory restrictions)'
$traces = Invoke-Kdu @('--json', 'traces')
$cleanable = $true
try {
    $report = $traces.output | ConvertFrom-Json
    $bad = @($report.findings | Where-Object { $_.category -in @('service', 'registry', 'file') })
    if ($bad.Count -gt 0) { $cleanable = $false }
} catch { }
Add-Result 'cleanup/traces' ($traces.code -eq 0 -and $cleanable) 'service/registry/file traces cleaned'

$failed = @($results | Where-Object { -not $_.ok }).Count
$document = [ordered]@{ suite = 'blook-kdu-e2e'; phase = 2; total = $results.Count
    failed = $failed; results = $results }
$document | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir 'result-2.json') -Encoding UTF8
if ($failed -ne 0) { exit 1 }
