# Release verification - blook-kdu 1.1.0

Build: kdu 1.1.0 with **140 bundled exploits** (118 memory-primitive + 22 kill-only).

Everything below was measured in the VMware lab guest (Windows 11 build 26200, test signing on, VulnerableDriverBlocklist off, drivers re-signed with the lab XINDA test certificate and staged through `BLOOK_KDU_DRIVER_DIR`). No driver was ever loaded on the host.

The matrix covers 121 of the bundled exploits. The 19 variants added after it ran (`winio_64a/b`, `winio_a_nz`, `winio_b/w`, `winio_edr`, `winio_elan`, `winio_ew1/2`, `winio_heaven`, `winio_tk`, `winio_ufu`, `wnbios_v1/v2`, `physmem_v2`, `glckio2_v1`, `asmio`, `winio_big1`, `winio_big2`) ship with mock-device unit tests and CI jobs but have no lab entry yet.

## Memory exploits (`kdu exploits test`)

- Authoritative full matrix: 34 PASS / 118 tested (docs/lab/20261022-final-all)
- Follow-up top-ups: 2 PASS (docs/lab/20261022-topup1)
- **Usable memory exploits: 36**

| memory PASS |
| --- |
| adlice_rootlaser |
| amd_pdfwkrnl |
| atszio64 |
| atszio64_v1 |
| binalyze_irec |
| cormem |
| cormem_v1 |
| cormem_v2 |
| cormem_v3 |
| dbutil23 |
| directio64 |
| directio64_2 |
| echodrv |
| eneio64 |
| enetechio64 |
| gdrv |
| glckio2 |
| hp_etdsupp_v1 |
| hp_etdsupport |
| inpoutx64 |
| intel_pmxdrv |
| ktapi |
| ktapi_v1 |
| marvinhw |
| matrox |
| msio64 |
| pgrhostcontrol |
| physmem64 |
| rtcore64 |
| sysdrv3s |
| truesight |
| winio_a |
| winio64 |
| winio64_2 |
| wnbios |
| wnbios_2 |

## Kill-only exploits (`kdu process kill`)

Kill-only drivers have no memory primitive, so `kdu exploits test` reports SKIP. They are verified by terminating a PPL-protected process (MsMpEng.exe / SecurityHealthService.exe / SgrmBroker.exe) with the driver.

- **Usable kill-only exploits: 14 / 22 verified** (docs/lab/20261022-kill-only2)

| kill-only PASS |
| --- |
| appremover |
| bdapiutil |
| goflydrv |
| hwaudioos2ec |
| k7rkscan1516 |
| libwasys |
| monprocessex |
| pctcore64 |
| stprocessmonitor114 |
| stprocessmonitor2618 |
| tfsysmon |
| unknown_eb |
| wsftprm |
| xkpsm |

## Usable total

**50 of 140 bundled exploits are verified usable in the lab VM** (36 memory + 14 kill-only). The 40-usable target is met; the remaining 90 are either documented as not usable in this guest below or are the 19 post-matrix variants that are unit-tested only so far.

## Not usable in this guest (documented, with evidence)

- Unsafe-physical family (`winring0`, `winiodrv_a/b`, `lha`, `phydmacc`, `winring0_v2`): the drivers lack an MmMapIoSpace result check; enabling `BLOOK_KDU_ALLOW_UNSAFE_PHYSICAL=1` lets the page walk proceed and the guest bugchecks. They are gated behind the opt-in and stay flagged `unsafe_physical_holes`.
- ASRock/RWE family (`asrock`, `asr*`, `axtudrv`, `appshopdrv103`): the drivers copy through a caller pointer; physical reads of ordinary pages can hang the guest (verified with `kdu --exploit asrock mem phys read 0x1AA000 8`). Translation is documented and left in place, but the drivers are not self-testable here.
- Access-controlled devices (`asusio2/3`, `sivx64`, `zodiacon_kobexp`, `ene2`): the driver itself validates the caller (trust list / DACL / SDDL) and returns 0x5/0xC0000022 on CreateFile.
- Revoked originals (`gmer`, `mimidrv`, `mhyprot2`): re-signed images carry a single valid XINDA signature; the guest still returns CERT_E_REVOKED, so the embedded vendor original is evidently what gets loaded (Defender tamper protection blocks excluding the staging path fully).
- Hardware-gated PnP drivers (`exarmpio`, `mil1553b`, `seacom_xr`, `ser15x`): devices are created only when the board is enumerated.
- Driver-init/build gated (`amd` 0x1F needs Ryzen hardware, `dbk64` 0x1F, `directio64_2` registry parameters, `lenovo_msrio` bugchecks the guest, `procexp*`/`rzpnk` require a `\\Device\\PhysicalMemory` section handle that 26200 no longer exposes).
- Removed for honesty: `usassaio*` (the AsusSAIO builds have no physical-map IOCTL) and the phantom/zeroed corpus blobs that had no loadable PE were not shipped as exploits.

## Reproduce

```pwsh
pwsh scripts/vm-lab.ps1 -All -TestSigning -Out docs/lab/20261022-final-all --BatchLogEvery 10
pwsh tools/vm-lab/verify-kill-only.ps1 -Ids <kill-only ids> -Out docs/lab/20261022-kill-only2
pwsh tools/vm-lab/make-release-verification.ps1
```
