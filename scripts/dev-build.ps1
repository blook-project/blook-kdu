# blook-kdu: fast developer build (parallel-safe).
#
# Several agents/implementers work on disjoint exploit directories at the same
# time; xmake has a single build directory, so every build run is serialized on
# a global named mutex. Use this script instead of `xmake` directly.
#
#   pwsh scripts/dev-build.ps1 -Exploits nseckrnl,ktapi   # build + unit test 2 exploits
#   pwsh scripts/dev-build.ps1 -Full                      # build every target
#   pwsh scripts/dev-build.ps1 -Exploits foo -NoTests     # compile only
#
# It refreshes src/assets.rc and the exploit registry first (both are generated
# files; a new exploit directory is picked up automatically).
[CmdletBinding()]
param(
    [string[]] $Exploits = @(),
    [switch] $Full,
    [switch] $All,
    [switch] $NoTests,
    [switch] $Configure,
    [string] $Mode = 'release',
    [string] $KchannelDir = '',
    [string] $Wdk = 'Y:\Program Files (x86)\Windows Kits\10',
    [string] $Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path -LiteralPath $Root).Path
Set-Location $Root
# `pwsh -File dev-build.ps1 -Exploits a,b,c` arrives as one string; normalize.
$Exploits = @($Exploits | ForEach-Object { $_ -split '[,\s]+' } |
              Where-Object { $_ })
if ($All) { $Full = $true }

$mutex = New-Object System.Threading.Mutex($false, 'Global\blook-kdu-build')
$owned = $false
$failed = @()
try {
    $owned = $mutex.WaitOne([TimeSpan]::FromSeconds(1800))
    if (-not $owned) { throw 'timed out waiting for the blook-kdu build lock' }

    if (-not $KchannelDir) {
        $KchannelDir = Join-Path (Split-Path -Parent $Root) 'blook-kchannel'
    }
    $needsConfigure = $Configure -or -not (Test-Path (Join-Path $Root '.xmake/windows'))
    if ($needsConfigure) {
        $arguments = @('f', '-y', '-m', $Mode, "--kchannel_dir=$KchannelDir",
                       "--wdk=$Wdk")
        Write-Host ("xmake " + ($arguments -join ' '))
        & xmake @arguments
        if ($LASTEXITCODE -ne 0) { throw 'xmake configure failed' }
    }

    # generated files: driver asset table + exploit registry
    & pwsh -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts/prepare-assets.ps1') -Root $Root | Out-Null
    & pwsh -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'scripts/gen-exploit-registry.ps1') -Root $Root | Out-Null

    if ($Full -or $Exploits.Count -eq 0) {
        & xmake -y
        if ($LASTEXITCODE -ne 0) { throw 'xmake build failed' }
    } else {
        # xmake accepts one positional target per invocation; loop so a batch of
        # exploits builds in one locked section.
        foreach ($id in $Exploits) {
            if ($id -notmatch '^[a-z][a-z0-9_]{2,31}$') {
                throw "invalid exploit id '$id'"
            }
            $targets = @("kdu_exploit_$id")
            if (-not $NoTests) { $targets += "kdu_exploit_test_$id" }
            foreach ($target in $targets) {
                Write-Host "xmake build $target"
                & xmake build $target
                if ($LASTEXITCODE -ne 0) {
                    throw "xmake build failed for: $target"
                }
            }
        }
    }
} finally {
    if ($owned) { [void]$mutex.ReleaseMutex() }
    $mutex.Dispose()
}

if (-not $NoTests) {
    $outDir = Join-Path $Root "build/windows/x64/$Mode"
    $testIds = if ($Full -or $Exploits.Count -eq 0) {
        Get-ChildItem (Join-Path $Root 'tests/unit/exploits') -Filter '*_test.cpp' |
            ForEach-Object { $_.BaseName -replace '_test$', '' }
    } else {
        $Exploits
    }
    foreach ($id in $testIds) {
        $exe = Join-Path $outDir "kdu_exploit_test_$id.exe"
        if (-not (Test-Path $exe)) {
            Write-Warning "test binary missing: $exe"
            $failed += $id
            continue
        }
        Write-Host "== kdu_exploit_test_$id =="
        & $exe
        if ($LASTEXITCODE -ne 0) {
            Write-Host "FAILED: $id" -ForegroundColor Red
            $failed += $id
        }
    }
}

if ($failed.Count -gt 0) {
    Write-Host ("unit tests failed: " + ($failed -join ', ')) -ForegroundColor Red
    exit 1
}
Write-Host "dev-build ok"
