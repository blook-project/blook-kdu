# blook-kdu: clang-format helper.
#
#   pwsh scripts/format.ps1            # format all sources in place
#   pwsh scripts/format.ps1 -Check     # check only (CI)
#   pwsh scripts/format.ps1 -ClangFormat <path>
[CmdletBinding()]
param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot),
    [switch] $Check,
    [string] $ClangFormat = ''
)

$ErrorActionPreference = 'Stop'
Set-Location $Root

function Find-ClangFormat {
    if ($ClangFormat) { return $ClangFormat }
    $fromPath = Get-Command clang-format.exe -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    $candidates = @(
        (Join-Path $env:ProgramFiles 'LLVM/bin/clang-format.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'LLVM/bin/clang-format.exe')
    )
    $vsRoot = Join-Path $env:ProgramFiles 'Microsoft Visual Studio'
    if (Test-Path $vsRoot) {
        $found = Get-ChildItem $vsRoot -Recurse -Filter clang-format.exe `
                     -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $candidates += $found.FullName }
    }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) { return $candidate }
    }
    throw "clang-format not found; install LLVM or pass -ClangFormat <path>"
}

$clangFormat = Find-ClangFormat
Write-Host "using $clangFormat"
& $clangFormat --version

$files = Get-ChildItem include, src, tests -Recurse -File |
         Where-Object { $_.Extension -in @('.h', '.hpp', '.cpp', '.cc') } |
         ForEach-Object { $_.FullName }

$failures = @()
foreach ($file in $files) {
    if ($Check) {
        $output = & $clangFormat --dry-run --Werror $file 2>&1
        if ($LASTEXITCODE -ne 0) {
            $failures += $file
            Write-Host "not formatted: $file"
            Write-Host ($output | Out-String)
        }
    } else {
        & $clangFormat -i $file
        if ($LASTEXITCODE -ne 0) {
            $failures += $file
        }
    }
}

if ($failures.Count -gt 0) {
    throw "$($failures.Count) file(s) failed clang-format"
}
Write-Host ("clang-format ok: {0} file(s)" -f $files.Count)
