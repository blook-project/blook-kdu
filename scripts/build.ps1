# blook-kdu: one-command build.
#
#   pwsh scripts/build.ps1                                  # release, default paths
#   pwsh scripts/build.ps1 -Mode debug -KchannelDir <path> -Wdk <KitsRoot>
#
# Builds the whole toolkit (CLI, SDK, manual mapper, kernel payload embedded in
# the CLI, per-exploit libraries and all tests). blook-kchannel sources are
# required for the payload/IPC/SDK/CLI targets; the WDK is required for the
# kernel payload and the e2e guest driver.
[CmdletBinding()]
param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot),
    [ValidateSet('debug', 'release', 'releasedbg')]
    [string] $Mode = 'release',
    [string] $KchannelDir = '',
    [string] $Wdk = 'Y:\Program Files (x86)\Windows Kits\10',
    [switch] $NoTests
)

$ErrorActionPreference = 'Stop'
Set-Location $Root

if (-not $KchannelDir) {
    $KchannelDir = Join-Path (Split-Path -Parent $Root) 'blook-kchannel'
}
if (-not (Test-Path (Join-Path $KchannelDir 'include/blook/kchannel.h'))) {
    throw "blook-kchannel checkout not found at $KchannelDir (pass -KchannelDir)"
}
if (-not (Test-Path $Wdk)) {
    throw "WDK not found at $Wdk (pass -Wdk); the kernel payload needs it"
}

$arguments = @('f', '-y', '-m', $Mode,
               "--kchannel_dir=$KchannelDir", "--wdk=$Wdk")
if ($NoTests) { $arguments += '--build_tests=n' }
Write-Host ("xmake " + ($arguments -join ' '))
& xmake @arguments
if ($LASTEXITCODE -ne 0) { throw "xmake configure failed" }

& xmake -y
if ($LASTEXITCODE -ne 0) { throw "xmake build failed" }

& xmake run kdu_tests
if ($LASTEXITCODE -ne 0) { throw "host unit tests failed" }

foreach ($test in (Get-ChildItem (Join-Path $Root 'tests/unit/exploits') `
                       -Filter '*_test.cpp')) {
    $name = $test.BaseName -replace '_test$', ''
    & xmake run "kdu_exploit_test_$name"
    if ($LASTEXITCODE -ne 0) { throw "exploit test failed: $name" }
}
Write-Host "build + tests ok ($Mode)"

