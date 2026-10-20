# blook-kdu: build the canonical release/CI package.
#
# Produces artifacts/blook-kdu-<version>-windows-x64.zip with the layout the
# package registry expects (bin/, include/, lib/) plus docs/scripts, and a sibling
# .sha256 file.
[CmdletBinding()]
param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot),
    [string] $Configuration = 'release',
    [string] $Version = '',
    [string] $BuildDir = ''
)

$ErrorActionPreference = 'Stop'
Set-Location $Root

if (-not $Version) {
    $Version = (Get-Content (Join-Path $Root 'version.txt') -Raw).Trim()
}
if (-not $BuildDir) {
    $BuildDir = Join-Path $Root "build/windows/x64/$Configuration"
}
if (-not (Test-Path $BuildDir)) {
    throw "build directory not found: $BuildDir (run xmake -y first)"
}

$packageName = "blook-kdu-$Version-windows-x64"
$artifactDir = Join-Path $Root 'artifacts'
$staging = Join-Path $artifactDir $packageName
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Force $staging | Out-Null

function Copy-IfExists([string] $source, [string] $destination) {
    if (Test-Path $source) {
        $parent = Split-Path -Parent $destination
        if ($parent -and -not (Test-Path $parent)) {
            New-Item -ItemType Directory -Force $parent | Out-Null
        }
        Copy-Item $source $destination -Force
    } else {
        Write-Warning "missing build output: $source"
    }
}

# bin/
Copy-IfExists (Join-Path $BuildDir 'kdu.exe') (Join-Path $staging 'bin/kdu.exe')
Copy-IfExists (Join-Path $BuildDir 'kdu_payload.sys') (Join-Path $staging 'bin/kdu_payload.sys')

# include/
$includeSource = Join-Path $Root 'include/blook/kdu'
foreach ($header in Get-ChildItem $includeSource -Filter *.h) {
    $destination = Join-Path $staging "include/blook/kdu/$($header.Name)"
    New-Item -ItemType Directory -Force (Split-Path -Parent $destination) | Out-Null
    Copy-Item $header.FullName $destination -Force
}

# lib/ (static SDK + component libraries for embedding)
$libraries = @('kdu_sdk', 'kdu_exploits', 'kdu_exploit_common', 'kdu_loader',
               'kdu_ipc', 'kdu_base')
New-Item -ItemType Directory -Force (Join-Path $staging 'lib') | Out-Null
foreach ($library in $libraries) {
    Copy-IfExists (Join-Path $BuildDir "$library.lib") (Join-Path $staging "lib/$library.lib")
}

# metadata and docs
foreach ($file in @('README.md', 'CHANGELOG.md', 'LICENSE')) {
    Copy-IfExists (Join-Path $Root $file) (Join-Path $staging $file)
}
New-Item -ItemType Directory -Force (Join-Path $staging 'docs') | Out-Null
foreach ($doc in Get-ChildItem (Join-Path $Root 'docs') -File) {
    Copy-Item $doc.FullName (Join-Path $staging "docs/$($doc.Name)") -Force
}
New-Item -ItemType Directory -Force (Join-Path $staging 'xmake-package') | Out-Null
Copy-Item (Join-Path $Root 'xmake-package/xmake.lua') `
          (Join-Path $staging 'xmake-package/xmake.lua') -Force
Copy-Item (Join-Path $Root 'scripts') (Join-Path $staging 'scripts') -Recurse -Force

$zip = Join-Path $artifactDir "$packageName.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zip -CompressionLevel Optimal

$hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
$hashFile = "$zip.sha256"
Set-Content -Path $hashFile -Value ("{0}  {1}" -f $hash, (Split-Path -Leaf $zip)) -Encoding ASCII
Write-Host "package: $zip"
Write-Host "sha256 : $hash"
