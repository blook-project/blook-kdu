# blook-kdu: verify that version.txt, include/blook/kdu/version.h and xmake.lua
# agree on the project version.
[CmdletBinding()]
param(
    [string] $Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$version = (Get-Content (Join-Path $Root 'version.txt') -Raw).Trim()
$header = Get-Content (Join-Path $Root 'include/blook/kdu/version.h') -Raw
$xmake = Get-Content (Join-Path $Root 'xmake.lua') -Raw

$failures = @()
if ($header -notmatch ('BLOOK_KDU_VERSION_STRING\s+"' + [regex]::Escape($version) + '"')) {
    $failures += "include/blook/kdu/version.h does not contain BLOOK_KDU_VERSION_STRING `"$version`""
}
if ($xmake -notmatch ('set_version\("' + [regex]::Escape($version) + '"\)')) {
    $failures += "xmake.lua does not contain set_version(`"$version`")"
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}
Write-Host "version $version is consistent"
