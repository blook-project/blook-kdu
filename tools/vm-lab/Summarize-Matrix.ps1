# blook-kdu VM lab: summarize and sanity-check a matrix.json produced by
# scripts/vm-lab.ps1. Read-only: it never touches the VM.
#
#   pwsh tools/vm-lab/Summarize-Matrix.ps1 -Matrix docs/lab/20261022-final-108/matrix.json
#   pwsh tools/vm-lab/Summarize-Matrix.ps1 -Matrix <path> -Markdown <path> -Raw
#
# Checks performed:
#   * PASS rows must have a plausible ntoskrnl base and backend=driver and a raw
#     log that actually contains a PASS line for that id (guards against a
#     harness bug reporting PASS on nothing).
#   * kill-only drivers (process_kill capability, no memory capability) must be
#     SKIP, not PASS/FAIL; mismatches are reported.
#   * rows whose raw log contradicts the matrix status are listed as suspicious.
#   * failures are grouped by classification and vendor so the report is
#     actionable per implementer.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Matrix,
    [string] $Markdown = '',
    [string] $Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [switch] $Raw
)

$ErrorActionPreference = 'Stop'
$Matrix = (Resolve-Path -LiteralPath $Matrix).Path
$Root = (Resolve-Path -LiteralPath $Root).Path
$rows = @(Get-Content -LiteralPath $Matrix -Raw | ConvertFrom-Json)
if ($rows.Count -eq 0) { throw "matrix is empty: $Matrix" }
$matrixDir = Split-Path -Parent $Matrix

# Exploit inventory gives us vendor/capabilities for grouping + kill-only checks.
$inventory = @()
$kdu = Join-Path $Root 'build/windows/x64/release/kdu.exe'
if (Test-Path $kdu) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $json = & $kdu --json exploits list 2>&1 | Out-String } finally {
        $ErrorActionPreference = $previous
    }
    try { $inventory = @($json | ConvertFrom-Json) } catch { }
}
$meta = @{}
foreach ($item in $inventory) {
    $caps = @($item.capabilities)
    $memory = @($caps | Where-Object { $_ -match 'physical|virtual|map_physical|msr|io' })
    $meta[[string]$item.id] = @{
        vendor = [string]$item.vendor
        capabilities = $caps
        kill_only = (($caps -contains 'process_kill') -and $memory.Count -eq 0)
    }
}

$statusCounts = [ordered]@{}
foreach ($status in @('PASS', 'FAIL', 'CRASH', 'TIMEOUT', 'SKIP')) {
    $statusCounts[$status] = @($rows | Where-Object { $_.status -eq $status }).Count
}
$byClass = @{}
foreach ($row in $rows) {
    $key = if ($row.classification) { [string]$row.classification } else { 'pass' }
    if (-not $byClass.ContainsKey($key)) { $byClass[$key] = 0 }
    $byClass[$key]++
}
$passRows = @($rows | Where-Object { $_.status -eq 'PASS' })
$failRows = @($rows | Where-Object { $_.status -in @('FAIL', 'CRASH', 'TIMEOUT') })
$skipRows = @($rows | Where-Object { $_.status -eq 'SKIP' })

# ---------------------------------------------------------------------------
# Sanity checks on PASS rows
# ---------------------------------------------------------------------------
$suspicious = New-Object System.Collections.Generic.List[string]
foreach ($row in $passRows) {
    $problems = @()
    if (-not $row.ntoskrnl -or "$($row.ntoskrnl)" -notmatch '^0x[0-9a-fA-F]{6,}$') {
        $problems += "ntoskrnl missing/invalid ('$($row.ntoskrnl)')"
    }
    if ($row.backend -ne 'driver') { $problems += "backend='$($row.backend)'" }
    $rawPath = [string]$row.raw
    if ($rawPath -and -not [IO.Path]::IsPathRooted($rawPath)) {
        # vm-lab.ps1 may have been invoked with a workspace-relative -Out.
        $fromRoot = Join-Path $Root $rawPath
        if (Test-Path -LiteralPath $fromRoot) { $rawPath = $fromRoot }
        else { $rawPath = Join-Path (Split-Path -Parent $Root) $rawPath }
    }
    if (-not $rawPath -or -not (Test-Path -LiteralPath $rawPath)) {
        $problems += "raw log missing ($rawPath)"
    } else {
        $rawText = Get-Content -LiteralPath $rawPath -Raw
        if ($rawText -notmatch ("(?m)^\s*PASS\s+" + [regex]::Escape([string]$row.id) + "\b")) {
            $problems += 'raw log has no PASS line for this id'
        }
        if ($rawText -match '(?m)^\s*FAIL\s+') { $problems += 'raw log also contains a FAIL line' }
    }
    if ($problems.Count -gt 0) {
        $suspicious.Add(("{0}: {1}" -f $row.id, ($problems -join '; ')))
    }
}
foreach ($row in $rows) {
    if ($meta.ContainsKey([string]$row.id) -and $meta[[string]$row.id].kill_only -and
        $row.status -ne 'SKIP') {
        $suspicious.Add(("{0}: kill-only driver has status {1} (expected SKIP)" -f $row.id, $row.status))
    }
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# VM lab matrix summary: $(Split-Path -Leaf $matrixDir)")
$lines.Add('')
$lines.Add(("total={0}  PASS={1}  FAIL={2}  CRASH={3}  TIMEOUT={4}  SKIP={5}" -f
    $rows.Count, $statusCounts['PASS'], $statusCounts['FAIL'], $statusCounts['CRASH'],
    $statusCounts['TIMEOUT'], $statusCounts['SKIP']))
$lines.Add('')
$lines.Add('## PASS rows (' + $passRows.Count + ')')
$lines.Add('')
if ($passRows.Count -eq 0) {
    $lines.Add('(none)')
} else {
    $byVendor = $passRows | Group-Object { $v = ''; if ($meta.ContainsKey([string]$_.id)) { $v = $meta[[string]$_.id].vendor }; if (-not $v) { $v = 'unknown' }; $v } |
        Sort-Object Name
    foreach ($group in $byVendor) {
        $lines.Add(("- **{0}** ({1}): {2}" -f $group.Name, $group.Count,
            (($group.Group | ForEach-Object { $_.id }) -join ', ')))
    }
}
$lines.Add('')
$lines.Add('## Failures by classification')
$lines.Add('')
foreach ($key in ($byClass.Keys | Sort-Object { -$byClass[$_] })) {
    if ($key -eq 'pass' -or $key -eq 'skipped-no-primitive') { continue }
    $bucketRows = @($rows | Where-Object { $_.classification -eq $key })
    $lines.Add(("### {0} ({1})" -f $key, $bucketRows.Count))
    $lines.Add('')
    $lines.Add('| id | driver | detail | likely cause | raw |')
    $lines.Add('| --- | --- | --- | --- | --- |')
    foreach ($row in $bucketRows) {
        $lines.Add(("| {0} | {1} | {2} | {3} | {4} |" -f $row.id, $row.driver_file,
            (([string]$row.detail) -replace '\|', '/' -replace "`r|`n", ' '),
            (([string]$row.likely_cause) -replace '\|', '/' -replace "`r|`n", ' '), $row.raw))
    }
    $lines.Add('')
}
if ($skipRows.Count -gt 0) {
    $lines.Add('## SKIP rows (' + $skipRows.Count + ')')
    $lines.Add('')
    $lines.Add((($skipRows | ForEach-Object { $_.id }) -join ', '))
    $lines.Add('')
}
$lines.Add('## Sanity checks')
$lines.Add('')
if ($suspicious.Count -eq 0) {
    $lines.Add('- PASS rows all have a valid ntoskrnl, backend=driver and a raw log with a PASS line.')
    $lines.Add('- kill-only drivers are SKIP as expected.')
} else {
    $lines.Add('- SUSPICIOUS:')
    foreach ($item in $suspicious) { $lines.Add(("  - " + $item)) }
}

$report = $lines -join "`r`n"
Write-Output $report
if ($Markdown) {
    $Markdown = if ([IO.Path]::IsPathRooted($Markdown)) { $Markdown }
                else { Join-Path $matrixDir $Markdown }
    Set-Content -LiteralPath $Markdown -Value $report -Encoding utf8
    Write-Output ''
    Write-Output "wrote $Markdown"
}
