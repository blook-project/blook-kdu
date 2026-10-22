# blook-kdu VM lab — baseline run 2026-10-22 (108 exploits)

Guest-only verification of every compiled exploit: each driver was re-signed with
the lab XINDA test certificate, loaded into a disposable bvmenv guest, and
exercised with `kdu exploits test <id>` (driver load + kernel module enumeration
+ kernel virtual read of the ntoskrnl image header). The host never loaded a
driver; the run bugchecked the guest once (`lenovo_msrio`) and the harness reset
and recovered it automatically.

## Environment

| Item | Value |
| --- | --- |
| VM | `vm-byovd` (bvmenv 0.1.0, sha256 `0ab3c34b…`) |
| Guest | Windows `10.0.26200` build 26200 (host name BLOOK-BASE) |
| Host kernel | Windows 11 26200 |
| kdu.exe | `1.1.0`, sha256 `68875b40ec4ab8657a504a10cd178c7a623fa4c9b14ae80f137e22fd17244234` |
| Exploit ids in the binary | 108 (signing cache: 108 drivers) |
| Lab kernel config | `testsigning=Yes`, `nointegritychecks=Yes`, `VulnerableDriverBlocklistEnable=0` (guest snapshot, lab-only) |
| Driver signing | every `src/exploits/<id>/data/*.bin` re-signed with `signer/spcsign` + legacy XINDA SPC cert into `build/generated/signed-drivers/<driver_file>`; XINDA leaf exported to `build/generated/certs/xinda-leaf.cer`; guest trust stores: root ← `tsa-root.cer`, CA ← two VeriSign chain certs, trustedpublisher ← XINDA leaf |
| Defender | guest tamper protection is on, so realtime/IOAV cannot be turned off; `C:\byovd` and `%TEMP%` are excluded, which is what keeps the staged drivers from being quarantined (`PREP status=warn`, by design) |
| Driver source override | `BLOOK_KDU_DRIVER_DIR=C:\byovd\drivers` set in `C:\byovd\run-test.cmd`; `ServiceHost` loads `<dir>\<driver_file>` instead of the embedded RCDATA image |
| Timeout | 90 s per id, one elevated `bvmenv exec` per id + `bvmenv state` crash probe |
| Run | `pwsh scripts/vm-lab.ps1 -All -TestSigning -Out docs/lab/20261022-final-108 --BatchLogEvery 5` (07:10–08:00 local) |

## Totals

**108 ids: 23 PASS, 62 FAIL, 1 CRASH, 0 TIMEOUT, 22 SKIP**

- `SKIP` = 22 kill-only drivers (EDR/AV process-kill modules with no kernel
  memory primitive): `appremover, bdapiutil, ccprotect, enportv, gamedriverx64,
  goflydrv, honos2ec, hwaudioos2ec, k7rkscan1516, k7rkscan2310, ksapi64,
  libwasys, monprocessex, nseckrnl, pctcore64, stprocessmonitor114,
  stprocessmonitor2618, tfsysmon, unknown_eb, viragt64, wsftprm, xkpsm`.
- `CRASH` = `lenovo_msrio` (guest became unresponsive during the test; `bvmenv
  state` itself timed out, no stop code could be captured; VM reset + recovered
  automatically, remaining ids continued).

## PASS list (23), grouped by vendor

| Family / vendor | ids |
| --- | --- |
| Adlice | `adlice_rootlaser` |
| AMD | `amd_pdfwkrnl` |
| ASRock | `glckio2` |
| ASUSTeK | `atszio64` |
| ENE Technology | `enetechio64` |
| FLIR / Point Grey | `eneio64`, `pgrhostcontrol`, `wnbios` |
| GIGABYTE | `gdrv` |
| HP | `hp_etdsupport` |
| Huawei | `physmem64` |
| Inspect Element (Echo) | `echodrv` |
| Kontron | `ktapi` |
| Marvin Test Solutions | `marvinhw` |
| Matrox | `matrox` |
| MICSYS | `msio64` |
| MSI | `rtcore64` |
| PassMark | `directio64` |
| Highresolution/Red Fox | `inpoutx64` |
| Teledyne DALSA | `cormem` |
| TrueSight | `truesight` |
| WinIO (Yariv Kaplan) | `winio64`, `winio64_2` |

All 23 PASS rows were sanity-checked: `ntoskrnl` is a plausible kernel base
(`0xfffff800c8800000` or `0xfffff804ed800000`), `backend=driver`, and the raw log
contains a real `PASS <id> …` line. No bogus PASS was found.

## Failure classification (62 FAIL + 1 CRASH)

### 1. primitive-failed — 42 ids (driver loads, kernel memory read fails)

Most report `cannot read ntoskrnl image header` (39 ids):
`aida64, alcpu, amd_affdriver, amd_aod215, appshopdrv103, asr_autochkupd,
asr_ibdrv, asr_omgdrv, asr_rapidstart, asrdrv10, asrdrv106, asrdrv107,
asrdrv109, asrock, axtudrv, binalyze_irec, evga_eleetx1, hp_hpwks, hwrwdrv,
intel_nal, intel_pmxdrv, ipctype, leco, lenovo_ldd, lha, nvidia_nvoclock,
rtkio64, rtkiow10x64, rtkiow8x64, sysdrv3s, tpup_throttlestop, tpw, usassaio,
usassaio_sci, usassaio_v2, winhwdrv, winiodrv_a, winiodrv_b, winring0`.

Three report `the System process has no \Device\PhysicalMemory section handle`:
`procexp, procexp1702, rzpnk` (handle-duplication path, different primitive).

Owner: exploit implementers — the driver loads and the device opens, but the
read/translate IOCTL path returns no data (or the page walk built on it fails).
This is not a signing/lab problem; other physical-only drivers (`ktapi`,
`physmem64`, `directio64`, `msio64`, `atszio64`) PASS through the same page walk.
`hwrwdrv/winhwdrv/winring0/winiodrv_*` are additionally unsafe-hole physical
drivers: their page walk is intentionally guarded unless
`BLOOK_KDU_ALLOW_UNSAFE_PHYSICAL=1` (they fail cleanly instead of hanging the VM).

### 2. device-open-failed — 9 ids (driver loaded, device/IOCTL path did not open)

| id | exact error |
| --- | --- |
| asusio2 | `CreateFile(\\.\Asusgio2) failed: 0x00000005 (access denied)` |
| asusio3 | `CreateFile(\\.\Asusgio3) failed: 0x00000005 (access denied)` |
| sivx64 | `CreateFile(\\.\GLOBALROOT\Device\SIVDRIVER) failed: 0x00000005 (access denied)` |
| zodiacon_kobexp | `CreateFile(\\.\KObjExp) failed: 0x00000005 (access denied)` |
| dbutildrv2 | `\\.\DBUtil_2_5 did not appear` |
| exarmpio | `\\.\GLOBALROOT\Device\ComGPIO did not appear` |
| mil1553b | `\\.\GLOBALROOT\Device\CHR31X1X-A did not appear` |
| seacom_xr | `\\.\seacomxr did not appear` |
| ser15x | `\\.\GLOBALROOT\Device\ser15x did not appear` |

Owner: implementers (device name/SDDL/ACL, or the driver only creates its device
when the hardware is present). For serial/1553/GPIO modules (`ser15x`,
`seacom_xr`, `mil1553b`, `exarmpio`, `chr34x05`) the device is hardware-gated;
those modules can only pass on a guest that models the hardware.

### 3. blocked-revoked — 3 ids (CERT_E_REVOKED, `0x800B010C`)

`gmer`, `mhyprot2`, `mimidrv`
(e.g. `cannot start service 'gmerdrv': StartService failed: 证书已被颁发者直接吊销。 (0x800B010C)`).

These are the residual signature cases: the guest is in test signing and the
blocklist is off, yet the image is still rejected as revoked. Worth a targeted
investigation (likely a second/leftover signature entry in those three blobs, or
a driver that re-validates its own image) — see “known limitations”.

### 4. driver-start-failed — 3 ids (DriverEntry/init failure, hardware/build)

| id | exact error |
| --- | --- |
| amd | `cannot start service 'AMDRyzenMasterDriver': 0x0000001F (ERROR_GEN_FAILURE)` — needs AMD Ryzen hardware |
| dbk64 | `cannot start service 'CEDRIVER73': 0x0000001F` — driver init refuses this build |
| directio64_2 | `cannot start service 'DirectIo64_2': 0x00000057 (ERROR_INVALID_PARAMETER)` — service/start parameters |

### 5. service-create-failed — 2 ids (`0x430 ERROR_SERVICE_MARKED_FOR_DELETE`)

`chr34x05`, `dbutil23` — stale SCM service from an earlier attempt, no active
driver. The harness now retries these once automatically after
`sc stop && sc delete` (3 s backoff), so the next run should clear them.

### 6. fail-other — 2 ids (documented limits)

- `kph` — `kph supports Windows build 19044 at most (current 26200)` (build gate
  is intentional).
- `netease_neacsafe` — `NeacSafe64 service did not start (state=1, exit=2,
  start error=0x00000002)`: minifilter-style driver, needs the filter/service
  install path rather than a plain kernel service.

### 7. bugcheck / CRASH — 1 id

`lenovo_msrio` — the guest stopped answering during the test (`bvmenv state`
timed out; no stop code captured). The harness reset the snapshot, restored the
lab config (testsigning reboot) and continued; `recovered=true` in `summary.json`.
Treat as a driver-triggered bugcheck candidate for the implementer to minimise.

### 8. kdu-crashed — 1 id (new classification; was “unparsed” in this run)

`astra64` — `guest exit 0xC0000005` (`exit_code: -1073741819`): `kdu.exe` itself
died in user mode (access violation) while exercising this exploit's ioctl path.
The harness now labels this `kdu-crashed` instead of `unparsed`.

## Known limitations

- **Unsafe-hole physical drivers** (`winring0`, `winiodrv_a`, `winiodrv_b`,
  `hwrwdrv`, `winhwdrv`): page-table walks are only enabled with
  `BLOOK_KDU_ALLOW_UNSAFE_PHYSICAL=1` in the guest; by default they fail cleanly
  (primitive-failed) instead of hanging/bugchecking the VM. Re-test them with
  `-UnsafePhysical` on a disposable VM only.
- **Hardware-gated MMIO/serial modules** (`ser15x`, `seacom_xr`, `mil1553b`,
  `chr34x05`, `exarmpio`): no device is created without the modelled hardware;
  they fail at device open. `chr34x05` additionally hit the stale-service 0x430
  state and will be retried by the improved harness.
- **Minifilter drivers** (`netease_neacsafe`) are not loadable through the plain
  kernel-service path used by `exploits test`.
- **Build-gated drivers** (`kph` ≤ 19044) are expected to fail on 26200.
- **Residual revoked signatures** (`gmer`, `mhyprot2`, `mimidrv`): test signing +
  blocklist-off should accept every re-signed image; these three are the
  exception and need a look at the signed blob itself.
- **Guest is disposable**: the base snapshot has no testsigning; every reset
  restores it and the harness re-runs the lab-config steps (+ one reboot) before
  continuing. One crash cost ≈ 2–3 min.
- **Approximate flush semantics**: the harness records PASS/FAIL of the
  `exploits test` self-test (driver load + a small kernel VA read), not a full
  primitive-by-primitive matrix — use `kdu mem`/`kdu modules` tests for depth.

## Reproduce / inspect

```powershell
# whole matrix (sign cached by SHA256, ~30 min for 108 ids)
pwsh scripts/vm-lab.ps1 -All -TestSigning -Out docs/lab/20261022-final-108 --BatchLogEvery 5

# only the failed rows of that matrix (after fixes)
pwsh scripts/vm-lab.ps1 -RetryFailed -TestSigning -Out docs/lab/20261022-final-108

# read-only summary + PASS/failure sanity checks
pwsh tools/vm-lab/Summarize-Matrix.ps1 -Matrix docs/lab/20261022-final-108/matrix.json

# the unsafe-hole experiment (disposable VM only)
pwsh scripts/vm-lab.ps1 -Ids winring0,winiodrv_a,winiodrv_b,hwrwdrv,winhwdrv `
    -UnsafePhysical -NoSign -Out docs/lab/20261022-unsafe-physical
```

Artifacts in this directory: `matrix.json` (rows),
`matrix.md` (human table + actionable failures), `summary.json` (provenance,
crashes, per-id signed-driver hashes), `pipeline.log`, `prepare.log`,
`raw/<id>.log` (exact guest command + full stdout/stderr per id).
