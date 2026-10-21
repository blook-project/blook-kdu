# Publish a package version to the org xmake registry.
#
# Usage:
#   pwsh scripts/publish-registry.ps1 -Package blook-kdu -Version 1.0.1 `
#        -Zip artifacts/blook-kdu-1.0.1-windows-x64.zip
#   add -DryRun to only print the change.
#
# The registry lives at https://github.com/blook-project/blook-xmake-repo and is
# updated with the local `gh` credentials (no org secret needed on the dev host).
#
# Registry conventions (shared across blook-project packages):
#   * packages/<first-letter>/<pkg>/xmake.lua uses `add_versionfiles("versions.txt")`
#   * packages/<first-letter>/<pkg>/versions.txt holds "<version> <sha256>" lines
#     for *all* published versions, one per line
# This script keeps both in sync and never drops previously published versions.
[CmdletBinding()]
param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot),
    [string] $Package = 'blook-kdu',
    [Parameter(Mandatory = $true)][string] $Version,
    [string] $Zip = '',
    [string] $RegistryRepo = 'blook-project/blook-xmake-repo',
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'
Set-Location $Root

if (-not $Zip) {
    $Zip = Join-Path $Root "artifacts/$Package-$Version-windows-x64.zip"
}
if (-not (Test-Path $Zip)) {
    throw "release asset not found: $Zip"
}
$hash = (Get-FileHash $Zip -Algorithm SHA256).Hash.ToLower()
$assetName = Split-Path -Leaf $Zip

function New-Manifest([string] $packageName) {
    return @"
-- blook-project package: $packageName
-- Artifact: GitHub Release asset of blook-project/$packageName
-- hashes:   versions.txt  ("<version> <sha256>", updated by scripts/publish-registry.ps1)
package("$packageName")
    set_homepage("https://github.com/blook-project/$packageName")
    set_description("Self-contained Windows kernel driver exploitation toolkit with manual mapping, kernel payload and SDK")
    set_license("MIT")

    add_urls("https://github.com/blook-project/$packageName/releases/download/v`$(version)/$packageName-`$(version)-windows-x64.zip")
    add_versionfiles("versions.txt")

    on_install("windows", "x64", function (package)
        local installdir = package:installdir()
        for _, entry in ipairs({ "include", "lib", "bin", "share", "scripts" }) do
            if os.isdir(entry) then
                os.cp(entry, installdir)
            end
        end
        for _, docfile in ipairs(os.files("*.md")) do
            os.cp(docfile, installdir)
        end
        if os.isfile("LICENSE") then
            os.cp("LICENSE", installdir)
        end
    end)

    on_load(function (package)
        local installdir = package:installdir()
        if os.isdir(path.join(installdir, "include")) then
            package:add("includedirs", path.join(installdir, "include"))
        end
        for _, subdir in ipairs({ "lib/x64", "lib" }) do
            if os.isdir(path.join(installdir, subdir)) then
                package:add("linkdirs", path.join(installdir, subdir))
            end
        end
        for _, subdir in ipairs({ "bin/x64", "bin" }) do
            if os.isdir(path.join(installdir, subdir)) then
                package:add("bindirs", path.join(installdir, subdir))
            end
        end
    end)
package_end()
"@
}

# Merge existing versions.txt and any legacy inline add_versions lines.
function Read-Versions([string] $manifestPath, [string] $versionsPath) {
    $map = [ordered]@{}
    if (Test-Path $versionsPath) {
        foreach ($line in Get-Content $versionsPath) {
            if ($line -match '^\s*([0-9][0-9A-Za-z.\-+]*)\s+([0-9a-fA-F]{64})\s*$') {
                $map[$matches[1]] = $matches[2].ToLower()
            }
        }
    }
    if (Test-Path $manifestPath) {
        $content = Get-Content $manifestPath -Raw
        foreach ($match in [regex]::Matches($content, 'add_versions\("([^"]+)",\s*"([0-9a-fA-F]{64})"\)')) {
            $map[$match.Groups[1].Value] = $match.Groups[2].Value.ToLower()
        }
    }
    return $map
}

Write-Host "package : $Package $Version"
Write-Host "asset   : $assetName"
Write-Host "sha256  : $hash"

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("blook-registry-" + [guid]::NewGuid())
try {
    if ($DryRun) {
        Write-Host "--- dry run: manifest would use add_versionfiles(versions.txt) ---"
        $versions = Read-Versions '' ''
        $versions[$Version] = $hash
        $versions.GetEnumerator() | ForEach-Object { Write-Host ("  " + $_.Key + " " + $_.Value) }
        return
    }
    gh repo clone $RegistryRepo $temp -- --depth 1 | Out-Null
    $packageDir = Join-Path $temp "packages/$($Package[0])/$Package"
    New-Item -ItemType Directory -Force $packageDir | Out-Null
    $manifestPath = Join-Path $packageDir 'xmake.lua'
    $versionsPath = Join-Path $packageDir 'versions.txt'

    $versions = Read-Versions $manifestPath $versionsPath
    $versions[$Version] = $hash

    if (-not (Test-Path $manifestPath) -or
        (Get-Content $manifestPath -Raw) -notmatch 'add_versionfiles') {
        Set-Content -Path $manifestPath -Value (New-Manifest $Package) -Encoding UTF8
    }
    $lines = @($versions.GetEnumerator() |
               Sort-Object { [version]($_.Key -replace '-.*$', '') } |
               ForEach-Object { "$($_.Key) $($_.Value)" })
    Set-Content -Path $versionsPath -Value $lines -Encoding UTF8

    Push-Location $temp
    try {
        git add .
        $status = git status --porcelain
        if (-not $status) {
            Write-Host "registry already up to date: $Package $Version"
            return
        }
        git -c user.name="MicroBlock" `
            -c user.email="66859419+std-microblock@users.noreply.github.com" `
            commit -m "${Package}: publish $Version ($($hash.Substring(0, 12)))"
        git push origin HEAD
    } finally {
        Pop-Location
    }
    Write-Host "registry updated: $RegistryRepo packages/$($Package[0])/$Package (versions.txt now has $($versions.Count) version(s))"
} finally {
    if (Test-Path $temp) { Remove-Item $temp -Recurse -Force }
}
