# blook-kdu: verify embedded exploit driver blobs before they are embedded.
#
# The data directory is the single source of truth for the vulnerable drivers
# the toolkit ships. KDU-style driver packs are often stored compressed; those
# blobs must not be embedded directly (Windows would reject them with "no DOS
# signature"). This script fails the build/CI when a blob is not a valid x64 PE
# and when a .rc file references a missing binary.
[CmdletBinding()]
param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$exploitsDir = Join-Path $Root 'src/exploits'
$failures = @()
$checked = 0

foreach ($exploit in Get-ChildItem $exploitsDir -Directory) {
    if ($exploit.Name -in @('common', 'data')) { continue }
    $dataDir = Join-Path $exploit.FullName 'data'
    if (-not (Test-Path $dataDir)) { continue }
    foreach ($bin in Get-ChildItem $dataDir -Filter '*.bin') {
        $bytes = [System.IO.File]::ReadAllBytes($bin.FullName)
        $checked++
        if ($bytes.Length -lt 0x40) {
            $failures += "$($exploit.Name)/$($bin.Name): too small ($($bytes.Length) bytes)"
            continue
        }
        if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
            $failures += ("{0}/{1}: no MZ signature (head {2:X2}-{3:X2}); use the " +
                          "decompressed driver blob") -f $exploit.Name, $bin.Name,
                          $bytes[0], $bytes[1]
            continue
        }
        $e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
        if ($e_lfanew -le 0 -or $e_lfanew + 0x18 -gt $bytes.Length) {
            $failures += "$($exploit.Name)/$($bin.Name): broken e_lfanew"
            continue
        }
        if ([BitConverter]::ToUInt32($bytes, $e_lfanew) -ne 0x00004550) {
            $failures += "$($exploit.Name)/$($bin.Name): missing PE signature"
            continue
        }
        $machine = [BitConverter]::ToUInt16($bytes, $e_lfanew + 4)
        if ($machine -ne 0x8664) {
            $failures += "$($exploit.Name)/$($bin.Name): not an x64 image"
            continue
        }
        # Optional header starts at e_lfanew+24; SizeOfImage is at +56.
        $sizeOfImage = [BitConverter]::ToUInt32($bytes, $e_lfanew + 24 + 56)
        if ($sizeOfImage -eq 0) {
            $failures += "$($exploit.Name)/$($bin.Name): SizeOfImage is zero"
        }
    }
    foreach ($rc in Get-ChildItem $dataDir -Filter '*.rc') {
        $content = Get-Content $rc.FullName -Raw
        foreach ($match in [regex]::Matches($content, '"([^"]+\.bin)"')) {
            $referenced = Join-Path $dataDir $match.Groups[1].Value
            if (-not (Test-Path $referenced)) {
                $failures += "$($exploit.Name)/$($rc.Name): references missing $($match.Groups[1].Value)"
            }
        }
    }
}

if ($checked -eq 0) {
    throw "no embedded driver blobs found under $exploitsDir"
}
if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Host ("FAIL " + $_) }
    throw ("{0} embedded asset problem(s), {1} blob(s) checked" -f $failures.Count, $checked)
}
Write-Host ("embedded assets ok: {0} driver blob(s) are valid x64 PEs" -f $checked)
