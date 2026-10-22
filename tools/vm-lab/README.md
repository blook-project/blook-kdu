# blook-kdu VM lab (tools/vm-lab)

Reproducible **guest-only** verification of every compiled exploit: the harness
loads the exploit's vulnerable driver and runs `kdu exploits test <id>` inside a
disposable bvmenv VMware guest, one `bvmenv exec` per exploit, and writes a
pass/fail matrix. The host never loads a driver — a bugcheck only costs one VM
reset.

- Runner: `scripts/vm-lab.ps1`
- Guest preparation (pushed to `C:\byovd\guest-prepare.ps1`): `tools/vm-lab/guest-prepare.ps1`
- Results: `<Out>/matrix.json`, `<Out>/matrix.md`, `<Out>/summary.json`,
  `<Out>/raw/<id>.log`, `<Out>/pipeline.log`, `<Out>/prepare.log`

## Prerequisites

| Requirement | Notes |
| --- | --- |
| bvmenv | `D:\blook-kernel-project\blook-vmware-environment\build\windows\x64\release\bvmenv.exe` (override with `-Bvmenv`). |
| VM | A disposable fork with VMware Tools running, e.g. `vm-byovd`. Never point this at a machine you care about: tests bugcheck the guest on purpose. |
| Guest tools | bvmenv guest ops (push/exec/state) work over VMCI; the guest needs no network. |
| Build inputs | `pwsh scripts/dev-build.ps1 -Full -NoTests` (xmake 3.0.8 from `Y:\Users\mbcloud\xmake`, WDK `Y:\Program Files (x86)\Windows Kits\10`, blook-kchannel at `..\blook-kchannel`). |
| Signing material | `signer/spcsign/spcsign.exe`, `signer/certs/*.cer`, `signer/tsa/tsa-root.cer`, and the XINDA code-signing certificate in the local certificate store (see `scripts/sign.ps1`). |
| kdu.exe | `build/windows/x64/release/kdu.exe`; the harness reads its exploit list (`kdu --json exploits list`) and pushes the same binary into the guest. |

## Lab-only driver-loading trick (why the re-signing exists)

The bundled vendor drivers are *real* vulnerable drivers: current Microsoft
policy revokes or blocklists most of them. Loading them as-shipped in the guest
fails with `0x800B010C` (CERT_E_REVOKED), `0xE1` (Defender,
ERROR_VIRUS_INFECTED), or `0x1F` (DriverEntry/hardware failure). The lab
sidesteps the policy entirely — **only in the disposable guest**:

1. **Re-sign every driver blob with the legacy XINDA SPC test certificate.**
   `scripts/sign.ps1` (via `signer/spcsign`) rewrites the Authenticode signature
   of `src/exploits/<id>/data/*.bin` into
   `build/generated/signed-drivers/<info.driver_file>`. The checked-in blobs and
   the release binary are never modified — only the generated cache.
2. **Trust the whole XINDA chain in the guest.** The chain is
   XINDA leaf → VeriSign Class 3 Code Signing 2010 CA → VeriSign Class 3 Public
   Primary CA G5 (cross-signed by Microsoft) and the countersignature chain
   Blook Local TSA → Blook Local TSA Root. `guest-prepare.ps1` imports:
   - `tsa-root.cer` → `root`
   - `verisign-cscs-2010.cer`, `verisign-g5-mcvr.cer` → `CA`
   - `xinda-leaf.cer` (exported from a signed driver with
     `Get-AuthenticodeSignature … .SignerCertificate.Export('Cert')`) →
     `trustedpublisher`
3. **Switch the guest to test signing.** The XINDA leaf is itself revoked, so
   DSE still rejects the re-signed images. `-TestSigning` sets
   `bcdedit /set testsigning on` **and** `bcdedit /set nointegritychecks on`,
   reboots the guest once, and re-runs the preparation. Recorded in
   `summary.json` as `testsigning=true`.
4. **Disable the Microsoft Vulnerable Driver Blocklist** (WDAC, not DSE —
   it survives test signing):
   `HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable = 0`.
   Also clears the CryptoAPI URL/CRL cache (`certutil -urlcache * delete`), so a
   stale revocation list cannot leak between runs.
5. **Defender**: realtime/IOAV off where the guest allows it (tamper protection
   often pins them on), plus exclusions for `C:\byovd` and `%TEMP%`. The
   exclusion is what actually keeps the staged drivers from being quarantined;
   the preparation reports `PREP status=warn` when only the policy part fails.

All of this is lab-only and disappears on `bvmenv reset` (snapshot revert), which
is why the harness re-runs preparation after every crash recovery.

## Incantations

```powershell
# Everything (sign + prepare + push + test), 60+ ids, first run after a reset
pwsh scripts/vm-lab.ps1 -All -TestSigning -Out docs/lab/20261022-baseline-60 --BatchLogEvery 5

# One exploit while an implementer iterates (serialized by the lab mutex)
pwsh scripts/vm-lab.ps1 -Ids tpw -TestSigning -Out docs/lab/tpw-check

# Resume: reuse the VM state, don't re-sign/re-push, merge into the old matrix
pwsh scripts/vm-lab.ps1 -Ids ktapi,amd -TestSigning -NoSign -NoPush -NoPrepare `
    -Result docs/lab/20261022-baseline-60/matrix.json -Out docs/lab/20261022-baseline-60

# Lab-only experiment: allow physical drivers with unsafe holes to page-walk
pwsh scripts/vm-lab.ps1 -Ids winring0,hwrwdrv,winhwdrv -UnsafePhysical -NoSign `
    -Out docs/lab/20261022-unsafe-physical

# Only the harness stages (no test run)
pwsh scripts/vm-lab.ps1 -Ids amd -NoSign -NoPush -NoPrepare -Out docs/lab/amd-only  # still tests
```

| Flag | Meaning |
| --- | --- |
| `-All` / `-Ids a,b` | every id from `kdu --json exploits list` / an explicit subset. |
| `-Out <dir>` | result directory (default `docs/lab/<yyyyMMdd-HHmm>-vm`). |
| `-TestSigning` | enable the lab kernel config (testsigning + nointegritychecks, blocklist off) and reboot the guest if needed. |
| `-NoSign` / `-NoPush` / `-NoPrepare` | skip the corresponding stage (reuse a staged VM). |
| `-NoReset` | never reset the VM; the run stops on the first crash and marks the rest SKIP. |
| `-TimeoutSeconds N` | per-id guest exec timeout (default 90 s). |
| `-BatchLogEvery N` | write `matrix.json` every N ids so a long run is resumable. |
| `-UnsafePhysical` | add `BLOOK_KDU_ALLOW_UNSAFE_PHYSICAL=1` to the guest runner (winring0/hwrwdrv/winhwdrv page-walk experiments only). |
| `-ForceSign` | ignore the SHA256 signing cache. |
| `-Result <matrix.json>` (alias `-MergeResult`) | merge previous rows before running (resume workflows). |
| `-RetryFailed` | read the existing `<Out>/matrix.json` (or `-Result`), select only rows with status FAIL/TIMEOUT/CRASH/ERROR/*empty*, re-run those and merge the new rows over the old ones. Use it to iterate on implementer fixes without redoing the whole matrix. |

There is also `tools/vm-lab/quick-matrix.ps1`: a minimal serialized runner for
small fix batches (`-Ids ... -Out <dir>`), assuming the guest is already prepared
and the drivers staged. It writes `quick-matrix.json` (`id,status,detail,raw`)
and, like the main runner, holds the same `Global\blook-kdu-vmlab` mutex. Use it
when you only need PASS/FAIL for a few ids and do not want the full sign/push/
crash-recovery machinery — the authoritative matrices are still produced by
`scripts/vm-lab.ps1`.

Transient failures are retried once automatically: when the failure detail
matches `0x430` / `ERROR_SERVICE_MARKED_FOR_DELETE`, or when classification is
`device-open-failed` with `did not appear`, the runner waits 3 s, runs
`sc stop <service> && sc delete <service>` in the guest, waits 3 s and re-runs
the id once (`retried=true` on the row).

**Mutual exclusion.** The runner holds the global named mutex
`Global\blook-kdu-vmlab` for its whole execution (up to 1 h), so parallel
implementers can safely call `pwsh scripts/vm-lab.ps1 -Ids <their-id>` — runs
queue instead of corrupting each other's VM state. Build serialization is a
separate mutex (`Global\blook-kdu-build`, used by `scripts/dev-build.ps1`); do not
rebuild kdu.exe while a matrix run is in flight.

## What the guest does per id

The runner pushes `C:\byovd\run-test.cmd` once per VM boot:

```bat
@echo off
set BLOOK_KDU_DRIVER_DIR=C:\byovd\drivers
C:\byovd\kdu.exe exploits test %1
exit /b %ERRORLEVEL%
```

`BLOOK_KDU_DRIVER_DIR` makes `ServiceHost` load
`C:\byovd\drivers\<info.driver_file>` instead of the embedded RCDATA resource
(if the file is missing it falls back to the embedded resource, so a partial push
still tests *something* — the signed dir always contains every selected id).
Then the harness runs `bvmenv exec vm-byovd --elevated --timeout N -- "C:\byovd\run-test.cmd <id>"`,
records stdout/stderr, and calls `bvmenv state vm-byovd --json --no-ocr` to detect
a bugcheck/hang (power != on, screen classification `bsod`/`hang`/`black` with no
guest heartbeat, or a state call that itself times out). On a crash: mark the id
`CRASH` with the stop code, `bvmenv reset`, `start`, `wait-ready`, re-push,
re-prepare (including the one testsigning reboot) and continue.

## Consuming the matrix (for implementers)

`matrix.json` is an array of rows — one per id, latest run wins:

```json
{
  "id": "ktapi",
  "status": "PASS",              // PASS | FAIL | CRASH | TIMEOUT | SKIP
  "classification": "pass",      // failure bucket, see below
  "likely_cause": "",            // one-line actionable hint
  "host_blocked": false,         // true for revoked/Defender/trust-store failures
  "backend": "driver",           // kdu session backend from the PASS line
  "ntoskrnl": "0xfffff803a2400000",
  "driver_file": "ktapi.sys",
  "exit": 0, "guest_exit": 0,
  "duration_ms": 19580,
  "detail": "ntoskrnl=0x… backend=driver",
  "raw": "…/raw/ktapi.log",      // exact command + full guest stdout/stderr
  "at": "2026-10-22T05:57:48+08:00",
  "crash_stop_code": ""
}
```

`summary.json` adds `totals` (per status), `by_classification`, `crashes`,
`signed_drivers` (source/output SHA256 per id) and build provenance
(`kdu_sha256`, `bvmenv_sha256`, guest build). `matrix.md` is the same data as a
human table plus an “Actionable failures” section.

Failure buckets (`classification`):

| Bucket | Likely cause / owner |
| --- | --- |
| `blocked-revoked` | CERT_E_REVOKED / `0x800B010C`; lab signing or test-signing not effective (harness/VM). |
| `blocked-defender` | `0xE1`; guest Defender exclusion not effective (harness/VM). |
| `blocked-untrusted-root` / `blocked-expired` / `blocked-chain` | Guest trust store incomplete or timestamp chain untrusted (harness/VM). |
| `driver-start-failed` | `0x1F`/ERROR_GEN_FAILURE, `StartService failed`: DriverEntry needs hardware/wrong build → exploit implementer. |
| `device-open-failed` | Driver loaded but its device name/IOCTL path is wrong → exploit implementer. |
| `primitive-failed` | Driver loaded but the memory primitive failed (translation/IOCTL) → exploit implementer. |
| `unsupported` | The exploit/backend reports "unsupported" on this build. |
| `bugcheck` + `CRASH` status | The driver bugchecked the guest; `crash_stop_code` has the bugcheck name/code. |
| `timeout` / `timeout-empty-output` | Exec did not return in `-TimeoutSeconds` (driver hang / very slow primitive; guest may be wedged). |

## Pitfalls seen in practice

- **`bvmenv exec` output truncation with unquoted `&&`.** A command line like
  `cmd /c a && b` passed through bvmenv loses the output of `a`. The harness
  avoids it by executing a static `.cmd` file, which also keeps the env var
  setup out of the command line.
- **Elevated exec is not instant.** Each id costs one `bvmenv exec` plus one
  `state` call (~18–20 s/id including driver load); 60 ids ≈ 20 min. Keep
  `-BatchLogEvery` small so a wedged run is resumable.
- **Snapshot revert undoes the lab config.** `bvmenv reset` restores the base
  snapshot: `C:\byovd` disappears, testsigning and the blocklist registry value
  revert. The harness re-pushes and re-prepares (one reboot) after every crash.
- **`bvmenv state` fails during a hang.** It can return
  `{"schema":"bvmenv.error.v1","error":"guest script failed (timeout)"}`; treat
  that as a crash and reset.
- **The screen classifier can call an idle lock screen `login`.** `bsod` is
  trusted; `black`/`hang` are only treated as crashes when the guest also stops
  answering.
- **`vmware.log` may warn about `DISKLIB-SPARSE … needs repair`** for a stale
  snapshot chain; the VM still boots. Ignore unless the guest stops booting.
- **Unsafe-hole physical drivers can hang the guest.** `winring0`/`hwrwdrv`/
  `winhwdrv` page walks are guarded by default (`BLOOK_KDU_ALLOW_UNSAFE_PHYSICAL`
  opt-in). Only set it with `-UnsafePhysical` on a disposable VM, and expect a
  reset afterwards.

## Adding a driver to the lab

Nothing to do beyond adding the exploit normally: put the vendor image at
`src/exploits/<id>/data/<name>.bin`, set `info.driver_file` to the name the
driver must be staged as, rebuild (`pwsh scripts/dev-build.ps1 -Full -NoTests`),
then `pwsh scripts/vm-lab.ps1 -Ids <id> -TestSigning -Out docs/lab/<id>-check`.
The harness picks the blob up from the inventory, signs it into
`build/generated/signed-drivers/<driver_file>`, pushes it and runs the test.
