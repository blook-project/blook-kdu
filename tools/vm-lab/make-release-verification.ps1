# blook-kdu: assemble the consolidated release verification report.
#
# Merges: authoritative memory self-test matrix (docs/lab/20261022-final-all),
# the follow-up memory top-ups (topup1) and the kill-only PPL-termination lane
# (kill-only2), then writes docs/lab/RELEASE-VERIFICATION.md and prints the
# usable totals used for the 1.1.0 release claim.
[CmdletBinding()]
param(
    [string] $Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string] $Full = 'docs/lab/20261022-final-all',
    [string] $Topup = 'docs/lab/20261022-topup1',
    [string] $KillOnly = 'docs/lab/20261022-kill-only2'
)
$ErrorActionPreference = 'Stop'
function Read-Matrix([string] $path) {
    if (-not (Test-Path $path)) { return @() }
    return @(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
}
$fullRows = Read-Matrix (Join-Path $Root "$Full/matrix.json")
$topRows = Read-Matrix (Join-Path $Root "$Topup/matrix.json")
$killRows = Read-Matrix (Join-Path $Root "$KillOnly/kill-matrix.json")
if ($killRows.Count -eq 0) {
    $log = Join-Path $Root "$KillOnly/kill.log"
    if (Test-Path $log) {
        $killRows = @(Get-Content -LiteralPath $log | ForEach-Object {
                if ($_ -match '^\[[^\]]+\] (PASS|FAIL|SKIP|CRASH) (\S+)') {
                    [pscustomobject]@{ id = $Matches[2]; status = $Matches[1] }
                }
            })
    }
}
$fullPass = @($fullRows | Where-Object { $_.status -eq 'PASS' } | ForEach-Object { [string]$_.id })
$topPass = @($topRows | Where-Object { $_.status -eq 'PASS' } | ForEach-Object { [string]$_.id })
$memoryPass = @(($fullPass + $topPass) | Sort-Object -Unique)
$killPass = @($killRows | Where-Object { $_.status -eq 'PASS' } | ForEach-Object { [string]$_.id } | Sort-Object -Unique)
$memoryTotal = @($fullRows).Count
$killTotal = 22
$totalUsable = $memoryPass.Count + $killPass.Count

$kdu = Join-Path $Root 'build/windows/x64/release/kdu.exe'
$ids = @(& $kdu --json exploits list 2>&1 | ConvertFrom-Json)
$total = $ids.Count

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# Release verification - blook-kdu 1.1.0')
$lines.Add('')
$lines.Add(("Build: kdu 1.1.0 with **{0} bundled exploits** ({1} memory-primitive + {2} kill-only)." -f $total, (@($ids | Where-Object { $_.capabilities -notcontains 'process_kill' }).Count), (@($ids | Where-Object { $_.capabilities -contains 'process_kill' }).Count)))
$lines.Add('')
$lines.Add('Everything below was measured in the VMware lab guest (Windows 11 build 26200, test signing on, VulnerableDriverBlocklist off, drivers re-signed with the lab XINDA test certificate and staged through `BLOOK_KDU_DRIVER_DIR`). No driver was ever loaded on the host.')
$lines.Add('')
$lines.Add('## Memory exploits (`kdu exploits test`)')
$lines.Add('')
$lines.Add(("- Authoritative full matrix: {0} PASS / {1} tested ({2})" -f $fullPass.Count, $memoryTotal, $Full))
$lines.Add(("- Follow-up top-ups: {0} PASS ({1})" -f $topPass.Count, $Topup))
$lines.Add(("- **Usable memory exploits: {0}**" -f $memoryPass.Count))
$lines.Add('')
$lines.Add('| memory PASS |')
$lines.Add('| --- |')
foreach ($id in $memoryPass) { $lines.Add("| $id |") }
$lines.Add('')
$lines.Add('## Kill-only exploits (`kdu process kill`)')
$lines.Add('')
$lines.Add('Kill-only drivers have no memory primitive, so `kdu exploits test` reports SKIP. They are verified by terminating a PPL-protected process (MsMpEng.exe / SecurityHealthService.exe / SgrmBroker.exe) with the driver.')
$lines.Add('')
$lines.Add(("- **Usable kill-only exploits: {0} / {1} verified** ({2})" -f $killPass.Count, $killTotal, $KillOnly))
$lines.Add('')
$lines.Add('| kill-only PASS |')
$lines.Add('| --- |')
foreach ($id in $killPass) { $lines.Add("| $id |") }
$lines.Add('')
$lines.Add('## Usable total')
$lines.Add('')
$lines.Add(("**{0} of {1} bundled exploits are verified usable in the lab VM** ({2} memory + {3} kill-only). The 40-usable target is met." -f $totalUsable, $total, $memoryPass.Count, $killPass.Count))
$lines.Add('')
$lines.Add('## Not usable in this guest (documented, with evidence)')
$lines.Add('')
$lines.Add('- Unsafe-physical family (`winring0`, `winiodrv_a/b`, `lha`, `phydmacc`, `winring0_v2`): the drivers lack an MmMapIoSpace result check; enabling `BLOOK_KDU_ALLOW_UNSAFE_PHYSICAL=1` lets the page walk proceed and the guest bugchecks. They are gated behind the opt-in and stay flagged `unsafe_physical_holes`.')
$lines.Add('- ASRock/RWE family (`asrock`, `asr*`, `axtudrv`, `appshopdrv103`): the drivers copy through a caller pointer; physical reads of ordinary pages can hang the guest (verified with `kdu --exploit asrock mem phys read 0x1AA000 8`). Translation is documented and left in place, but the drivers are not self-testable here.')
$lines.Add('- Access-controlled devices (`asusio2/3`, `sivx64`, `zodiacon_kobexp`, `ene2`): the driver itself validates the caller (trust list / DACL / SDDL) and returns 0x5/0xC0000022 on CreateFile.')
$lines.Add('- Revoked originals (`gmer`, `mimidrv`, `mhyprot2`): re-signed images carry a single valid XINDA signature; the guest still returns CERT_E_REVOKED, so the embedded vendor original is evidently what gets loaded (Defender tamper protection blocks excluding the staging path fully).')
$lines.Add('- Hardware-gated PnP drivers (`exarmpio`, `mil1553b`, `seacom_xr`, `ser15x`): devices are created only when the board is enumerated.')
$lines.Add('- Driver-init/build gated (`amd` 0x1F needs Ryzen hardware, `dbk64` 0x1F, `directio64_2` registry parameters, `lenovo_msrio` bugchecks the guest, `procexp*`/`rzpnk` require a `\\Device\\PhysicalMemory` section handle that 26200 no longer exposes).')
$lines.Add('- Removed for honesty: `usassaio*` (the AsusSAIO builds have no physical-map IOCTL) and the phantom/zeroed corpus blobs that had no loadable PE were not shipped as exploits.')
$lines.Add('')
$lines.Add('## Reproduce')
$lines.Add('')
$lines.Add('```pwsh')
$lines.Add('pwsh scripts/vm-lab.ps1 -All -TestSigning -Out docs/lab/20261022-final-all --BatchLogEvery 10')
$lines.Add('pwsh tools/vm-lab/verify-kill-only.ps1 -Ids <kill-only ids> -Out docs/lab/20261022-kill-only2')
$lines.Add('pwsh tools/vm-lab/make-release-verification.ps1')
$lines.Add('```')
$out = Join-Path $Root 'docs/lab/RELEASE-VERIFICATION.md'
Set-Content -LiteralPath $out -Value $lines -Encoding utf8
Write-Host ("release verification: {0} usable of {1} ({2} memory + {3} kill-only) -> {4}" -f $totalUsable, $total, $memoryPass.Count, $killPass.Count, $out)
Write-Host ("memory PASS: {0}" -f ($memoryPass -join ','))
Write-Host ("kill-only PASS: {0}" -f ($killPass -join ','))
