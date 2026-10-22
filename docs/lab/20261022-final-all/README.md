# blook-kdu VM lab — authoritative matrix 2026-10-22 (120 exploit build)

Guest-only verification of the release build: every compiled exploit's driver was
re-signed with the lab XINDA test certificate, loaded into a disposable bvmenv
guest, and exercised with `kdu exploits test <id>` (driver load → kernel module
enumeration → kernel virtual read of the ntoskrnl image header). The host never
loads a driver.

**118 of 120 ids were tested; 2 were excluded because their driver blobs are not
PE files** (`hp_etdsupp_v1`, `hp_etdsupp_v2`: `etdsupp_1.sys.bin` /
`etdsupp_2.sys.bin` start with 16 zero bytes, no `MZ`; `spcsign` refuses them and
the driver cannot be staged). See “Excluded” below.

## Environment

| Item | Value |
| --- | --- |
| VM | `vm-byovd` (bvmenv 0.1.0) |
| Guest | Windows `10.0.26200` build 26200 (host name BLOOK-BASE) |
| kdu.exe | `1.1.0`, sha256 `d425075feb588bbe3645115f6f439297941ba62ae071bb50e39c0578975e5395` (frozen 120-id build) |
| Exploit ids in binary | 120 (`kdu --json exploits list`) |
| Tested | 118 (all except the 2 excluded asset-invalid ids) |
| Lab kernel config | `testsigning=Yes`, `nointegritychecks=Yes`, `VulnerableDriverBlocklistEnable=0` (lab-only guest) |
| Driver signing | every `src/exploits/<id>/data/*.bin` re-signed with `signer/spcsign` + the legacy XINDA SPC cert into `build/generated/signed-drivers/<driver_file>`; XINDA leaf trusted via the guest `trustedpublisher` store; root ← `tsa-root.cer`, CA ← the two VeriSign chain certs |
| Defender | tamper protection on (realtime cannot be turned off); `C:\byovd` + `%TEMP%` excluded — that exclusion is what keeps the staged drivers from being quarantined (`PREP status=warn`, by design) |
| Driver source | `BLOOK_KDU_DRIVER_DIR=C:\byovd\drivers` in `C:\byovd\run-test.cmd`; `ServiceHost` loads `<dir>\<driver_file>` instead of the embedded RCDATA image |
| Timeout / method | 90 s per id, one elevated `bvmenv exec` per id + `bvmenv state` crash probe; crash → reset snapshot + re-push + re-prepare + continue |
| Command | `pwsh scripts/vm-lab.ps1 -Ids <118 ids> -TestSigning -Out docs/lab/20261022-final-all --BatchLogEvery 10` (09:04–09:50) |

## Totals

**118 ids: 34 PASS, 61 FAIL, 1 CRASH, 0 TIMEOUT, 22 SKIP**

- `SKIP` = 22 kill-only drivers (EDR/AV process-kill modules with no kernel
  memory primitive): `appremover, bdapiutil, ccprotect, enportv, gamedriverx64,
  goflydrv, honos2ec, hwaudioos2ec, k7rkscan1516, k7rkscan2310, ksapi64,
  libwasys, monprocessex, nseckrnl, pctcore64, stprocessmonitor114,
  stprocessmonitor2618, tfsysmon, unknown_eb, viragt64, wsftprm, xkpsm`.
- `CRASH` = `lenovo_msrio` (guest unresponsive; `bvmenv state` returned no data,
  no stop code available). The harness reset the snapshot, restored the lab
  config (testsigning reboot) and continued; `recovered=true`.
- `FAIL` = 61, all classified below.

## PASS list (34), grouped by vendor — all sanity-checked

Sanity: every PASS has `backend=driver`, a plausible kernel base
(`0xfffff807d4200000` before the lenovo_msrio crash/reset, `0xfffff801a1200000`
after it — so two bases are expected and correct), and a raw log containing the
exact `PASS <id> ntoskrnl=… backend=…` line. No bogus PASS.

| Family / vendor | ids |
| --- | --- |
| Adlice | `adlice_rootlaser` |
| AMD | `amd_pdfwkrnl` |
| ASRock | `glckio2` |
| ASUSTeK | `atszio64`, `atszio64_v1` |
| Binalyze | `binalyze_irec` |
| ENE Technology | `enetechio64` |
| FLIR / Point Grey | `eneio64`, `pgrhostcontrol`, `wnbios`, `wnbios_2` |
| GIGABYTE | `gdrv` |
| HP | `hp_etdsupport` |
| Huawei | `physmem64` |
| Inspect Element (Echo) | `echodrv` |
| Intel (ME tools) | `intel_pmxdrv` |
| Kontron | `ktapi`, `ktapi_v1` |
| Marvin Test Solutions | `marvinhw` |
| Matrox | `matrox` |
| MICSYS | `msio64` |
| MSI | `rtcore64` |
| PassMark | `directio64`, `directio64_2` |
| Highresolution / Red Fox | `inpoutx64` |
| SysDrv3S | `sysdrv3s` |
| Teledyne DALSA | `cormem`, `cormem_v1`, `cormem_v2`, `cormem_v3` |
| TrueSight | `truesight` |
| WinIO (Yariv Kaplan) | `winio_a`, `winio64`, `winio64_2` |

(34 ids / 26 distinct driver families — 8 ids are clone variants of an already
passing driver.)

## Failure classification (61 FAIL + 1 CRASH)

### 1. primitive-failed — 39 ids (driver loads, kernel memory primitive fails)

39 × `cannot read ntoskrnl image header`: `aida64, alcpu, amd_affdriver,
amd_aod215, appshopdrv103, asr_autochkupd, asr_ibdrv, asr_omgdrv,
asr_rapidstart, asrdrv10, asrdrv106, asrdrv107, asrdrv109, asrock, axtudrv,
cormem_v4, evga_eleetx1, hp_hpwks, hwrwdrv, intel_nal, ipctype, leco,
lenovo_ldd, lha, nvidia_nvoclock, phydmacc, rtkio64, rtkio64_2, rtkiow10x64,
rtkiow8x64, tpup_throttlestop, tpw, winhwdrv, winiodrv_a, winiodrv_b,
winring0` — plus the two `procexp`/`rzpnk` handle-search variants below.

- `procexp`: `no \Device\PhysicalMemory section handle found (handles=43510,
  candidates=4679, duplicate_failures=590, name_misses=4089)`;
  `procexp1702`: `the System process has no \Device\PhysicalMemory section
  handle`; `rzpnk`: same handle-search error (`handles=43241…`).
  These three are **driver-side/exploit-logic** (handle enumeration), not the
  page-walk translation path.
- `hwrwdrv`, `winhwdrv`, `winring0`, `winiodrv_a`, `winiodrv_b` are the
  unsafe-hole (WinRing0-class) physical drivers: their page walk is deliberately
  guarded unless `BLOOK_KDU_ALLOW_UNSAFE_PHYSICAL=1` (no `-UnsafePhysical` in
  this run; they fail cleanly instead of hanging the VM).
- The remaining 34 are the translation/read-path cluster (driver loaded, read of
  ntoskrnl did not return data) — the biggest remaining bucket for implementers.

### 2. device-open-failed — 8 ids (driver loads, device/IOCTL path does not open)

| id | exact error |
| --- | --- |
| asusio2 | `CreateFile(\\.\Asusgio2) failed: 0x00000005 (access denied)` |
| asusio3 | `CreateFile(\\.\Asusgio3) failed: 0x00000005 (access denied)` |
| ene2 | `CreateFile(\\.\EneTechIo) failed: 0x00000005 (access denied)` |
| sivx64 | `CreateFile(\\.\GLOBALROOT\Device\SIVDRIVER) failed: 0x00000005`; fallback: device present but not accessible with any access mask |
| zodiacon_kobexp | `CreateFile(\\.\KObjExp) failed: 0x00000005 (access denied)` |
| kph | `CreateFile(\?\GLOBALROOT\Device\KProcessHacker2) failed: 0x0000007B (invalid name)` — device path is malformed |
| directio_v2 | `\\.\DIRECTIO64 did not appear` (device-name variant mismatch) |
| directio64_v1 | `\\.\DIRECTIO64 did not appear` (device-name variant mismatch) |

### 3. service-create-failed — 7 ids (`0x430 ERROR_SERVICE_MARKED_FOR_DELETE`)

`chr34x05, dbutil23, dbutildrv2, exarmpio, mil1553b, seacom_xr, ser15x` —
stale SCM service from the immediately preceding failed attempt; the one-shot
retry (3 s + `sc stop/delete`) re-ran but the delete had not completed yet.
Harness-level (longer delete poll would clear it); for the serial/1553/GPIO
modules the next failure is expected to be device-open (hardware PnP-gated).

### 4. blocked-revoked — 3 ids (CERT_E_REVOKED, `0x800B010C`)

`gmer`, `mhyprot2`, `mimidrv`
(`StartService failed: 证书已被颁发者直接吊销。 (0x800B010C)`) — test signing and
blocklist-off should accept every re-signed image, so these three signed blobs
need a look (likely a second/leftover signature entry or a driver that
re-validates its own image).

### 5. driver-start-failed — 2 ids

- `amd` — `StartService failed: 0x0000001F` (needs AMD Ryzen hardware).
- `dbk64` — `StartService failed: 0x0000001F` (DriverEntry refuses 26200; the
  exploit's DBK registry-parameter fallback did not help because the driver
  never starts).

### 6. kdu-crashed — 1 id

`astra64` — `guest exit 0xC0000005`: `kdu.exe` died in user mode (access
violation) while exercising this exploit's IOCTL path; exploit-side bug.

### 7. fail-other / CRASH — 2 ids

- `netease_neacsafe` — `NeacSafe64 service did not start (state=1, exit=2,
  0x00000002)`: minifilter-style driver, not loadable through the plain kernel
  service path.
- `lenovo_msrio` — guest bugcheck/hang (`CRASH`, no stop code captured).

## Excluded (asset-invalid, not counted as FAIL)

- `hp_etdsupp_v1` — `src/exploits/hp_etdsupp_v1/data/etdsupp_1.sys.bin` is not a
  PE file (first 16 bytes `00`, no `MZ`; 29928 bytes).
- `hp_etdsupp_v2` — `src/exploits/hp_etdsupp_v2/data/etdsupp_2.sys.bin` is not a
  PE file (same symptom; 30288 bytes).
`spcsign` correctly fails on them (“not a PE file”), so they cannot be re-signed
or loaded. The pre-existing `hp_etdsupport` (`etdsupp.sys.bin`) is a valid PE and
PASSes.

## Release-claim status / near-miss list (driver-side, for one fix cycle)

34 PASS is below the “≥40 usable verified” target. Highest-return driver-side
failures that are **not** the page-walk/translation cluster:

| id | why it is close |
| --- | --- |
| `kph` | driver loads; only the device path is malformed (`\?\GLOBALROOT\…` → 0x7B). Fix the device name (`\\.\KProcessHacker2` or `\\?\GLOBALROOT\Device\…`) → likely PASS. |
| `directio_v2`, `directio64_v1` | driver loads; device name variants did not appear (`\\.\DIRECTIO64` / `LoopLpt`). Fix the device list → likely PASS. |
| `asusio2`, `asusio3`, `ene2`, `zodiacon_kobexp` | driver loads; `CreateFile` returns 0x5 (SDDL/access mask) — try additional access masks / `\\.\GLOBALROOT` name / SECURITY_ATTRIBUTES/open flags. |
| `sivx64` | device exists (create/start succeeded) but no access mask works — probe the SDDL/other aliases. |
| `procexp`, `procexp1702`, `rzpnk` | driver loads; exploit-side handle search does not find the `\Device\PhysicalMemory` section in System (counts in detail). Logic fix, not translation. |
| `astra64` | kdu.exe user-mode AV in the exploit's IOCTL path — fix the request layout/args. |
| `chr34x05`, `dbutil23`, `dbutildrv2`, `exarmpio`, `mil1553b`, `seacom_xr`, `ser15x` | only blocked by the transient 0x430 service state; a delete-poll retry would reveal their real device state (hardware-gated for the serial devices). |

## Known limitations (platform, not regressions)

- Unsafe-hole physical drivers (`winring0`, `winiodrv_a/b`, `hwrwdrv`,
  `winhwdrv`): page walk requires `BLOOK_KDU_ALLOW_UNSAFE_PHYSICAL=1`; excluded
  from this matrix on purpose (they can hang the guest).
- Hardware-gated MMIO/serial modules (`ser15x`, `seacom_xr`, `mil1553b`,
  `chr34x05`, `exarmpio`): no device without modelled hardware.
- Minifilter (`netease_neacsafe`) not loadable through the kernel-service path.
- `lenovo_msrio` bugchecks/hangs the guest — treat as a driver hazard.
- `dbk64`/`amd` refuse this build/hardware at DriverEntry.
- `gmer`/`mimidrv`/`mhyprot2` still report revoked although test signing is on.

## Reproduce / inspect

```powershell
# authoritative matrix (signing cache makes repeats cheap; ~40 min for 118 ids)
pwsh scripts/vm-lab.ps1 -All -TestSigning -Out docs/lab/20261022-final-all --BatchLogEvery 10

# only failures, after fixes (merges over matrix.json)
pwsh scripts/vm-lab.ps1 -RetryFailed -TestSigning -Out docs/lab/20261022-final-all

# read-only PASS/failure sanity checks
pwsh tools/vm-lab/Summarize-Matrix.ps1 -Matrix docs/lab/20261022-final-all/matrix.json
```

Artifacts: `matrix.json` (rows), `matrix.md` (human table + actionable
failures), `summary.json` (provenance, crash, per-id signed-driver hashes),
`pipeline.log`, `prepare.log`, `raw/<id>.log` (exact guest command +
stdout/stderr). Guest lab config was verified after the run: testsigning Yes,
nointegritychecks Yes, exclusions `C:\byovd` + `C:\Windows\Temp`.
