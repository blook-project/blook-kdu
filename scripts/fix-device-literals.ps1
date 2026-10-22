# blook-kdu: normalize info.device_name C++ literals (over-escaping safe).
#
# History: early scaffolds embedded the -Device value verbatim and later passes
# doubled backslashes, so some modules ended up with 4/8 backslashes before the
# dot ("\\\\.\\X" -> 8+4). The runtime value never had more than one real
# backslash, so repeated decode converges; after decoding to a stable runtime
# string we repair the Win32 prefix and encode exactly once.
[CmdletBinding()]
param([string] $Root = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path -LiteralPath $Root).Path

function Decode-Stable([string] $literal) {
    $runtime = $literal
    for ($i = 0; $i -lt 8; $i++) {
        $next = $runtime.Replace('\\', '\')
        if ($next -eq $runtime) { break }
        $runtime = $next
    }
    return $runtime
}

function Repair-Segment([string] $segment) {
    $seg = $segment.Trim()
    if ($seg -match '^\\\.\\') { return '\\.\' + $seg.Substring(3) }
    if ($seg -match '^\\GLOBALROOT\\') { return '\\.' + $seg }
    if ($seg -match '^\\Device\\') { return '\\.\\GLOBALROOT' + $seg }
    return $seg
}

function Repair-Runtime([string] $runtime) {
    $parts = $runtime -split ';'
    $fixed = @()
    foreach ($part in $parts) {
        if ([string]::IsNullOrWhiteSpace($part)) { continue }
        $fixed += (Repair-Segment $part)
    }
    return ($fixed -join ';')
}

function Encode([string] $runtime) {
    return $runtime.Replace('\', '\\')
}

$changed = @()
foreach ($dir in Get-ChildItem (Join-Path $Root 'src/exploits') -Directory) {
    if ($dir.Name -in @('common', 'data')) { continue }
    $cpp = Join-Path $dir.FullName "$($dir.Name).cpp"
    if (-not (Test-Path $cpp)) { continue }
    $text = Get-Content $cpp -Raw
    $new = [regex]::Replace($text, 'info\.device_name\s*=\s*"((?:[^"\\]|\\.)*)"', {
            param($m)
            $runtime = Decode-Stable $m.Groups[1].Value
            $repaired = Repair-Runtime $runtime
            $encoded = Encode $repaired
            'info.device_name = "' + $encoded + '"'
        })
    if ($new -ne $text) {
        [System.IO.File]::WriteAllText($cpp, $new,
            (New-Object System.Text.UTF8Encoding($false)))
        $changed += $dir.Name
    }
}

# Same repair for unit-test device assertions (== comparisons).
$changedTests = 0
foreach ($test in Get-ChildItem (Join-Path $Root 'tests/unit/exploits') -Filter '*_test.cpp') {
    $text = Get-Content $test.FullName -Raw
    $new = [regex]::Replace($text, 'info\.device_name\s*==\s*"((?:[^"\\]|\\.)*)"', {
            param($m)
            $runtime = Decode-Stable $m.Groups[1].Value
            $repaired = Repair-Runtime $runtime
            $encoded = Encode $repaired
            'info.device_name == "' + $encoded + '"'
        })
    if ($new -ne $text) {
        [System.IO.File]::WriteAllText($test.FullName, $new,
            (New-Object System.Text.UTF8Encoding($false)))
        $changedTests++
    }
}

Write-Host ("device literals repaired: {0} module(s), {1} test(s)" -f $changed.Count, $changedTests)
if ($changed.Count -gt 0) { Write-Host ($changed -join ', ') }
