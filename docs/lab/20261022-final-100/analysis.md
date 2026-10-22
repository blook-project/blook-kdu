# Early-FAIL analysis (final-100 matrix)

Author: impl-b. Scope: static analysis of the shipped/signed binaries + the
`raw/*.log` files of `docs/lab/20261022-final-100`. No driver was executed on
the host. At the time of writing the resumable matrix had produced 20 entries
(alphabetically up to `asusio2`); the conclusions below are for that slice and
for the ASRock family specifically, as requested by the Lead.

## 1. Result slice

| status | ids |
| --- | --- |
| PASS | `adlice_rootlaser`, `amd_pdfwkrnl` — both **native virtual read/write** |
| FAIL (device-open-failed) | `amd_aod215`, `asrdrv106`, `asrdrv107` |
| FAIL (primitive-failed) | `aida64`, `alcpu`, `amd_affdriver`, `appshopdrv103`, `asr_autochkupd`, `asr_ibdrv`, `asr_omgdrv`, `asr_rapidstart`, `asrdrv10`, `asrock`, `astra64` |

Correlation in this slice: **every** module that relies on `physical_read` for
kernel-VA access fails the self-test at the same step, including `asrock` (the
reference implementation these ports were cloned from) and `astra64` (which
shipped before this expansion). Every native `virtual_read` module passes.

## 2. Defect A (definitive) — broken C++ device-name literals

`raw/asrdrv106.log`:

```
FAIL asrdrv106  asrdrv106: cannot open device '\.AsrDrv106': device \.AsrDrv106 did not appear
```

The device string contains a single separator instead of `\\.\`. Cause: these
modules were scaffolded with `new-exploit.ps1 -Device '\\.\Name'`; the template
substitutes `@DEVICE@` textually into a C++ literal, so the file ends up with
`"\\.\Name"`, where `\N` is an invalid escape (MSVC warning C4129) and the
compiled string becomes `\.Name`. Unit tests only check `!device_name.empty()`,
so they stay green while the VM cannot open the device.

Fix: `info.device_name = "\\\\.\\Name";` (or scaffold with
`-Device '\\\\.\\Name'`).

All modules currently affected (from the full build log + a source scan):

| file:line | current literal | corrected |
| --- | --- | --- |
| `src/exploits/amd_aod215/amd_aod215.cpp:142` | `"\\.\AODDriver"` | `"\\\\.\\AODDriver"` |
| `src/exploits/asrdrv106/asrdrv106.cpp:143` | `"\\.\AsrDrv106"` | `"\\\\.\\AsrDrv106"` |
| `src/exploits/asrdrv107/asrdrv107.cpp:143` | `"\\.\AsrDrv107"` | `"\\\\.\\AsrDrv107"` |
| `src/exploits/asusio2/asusio2.cpp:182` | `"\\.\Asusgio2"` | `"\\\\.\\Asusgio2"` |
| `src/exploits/directio64_2/directio64_2.cpp:207` | `"\\.\DIRECTIO64"` | `"\\\\.\\DIRECTIO64"` |
| `src/exploits/eneio64/eneio64.cpp:182` | `"\\.\EneIo"` | `"\\\\.\\EneIo"` |
| `src/exploits/gamedriverx64/gamedriverx64.cpp:77` | `"\\.\HtAntiCheatDriver"` | `"\\\\.\\HtAntiCheatDriver"` |
| `src/exploits/ksapi64/ksapi64.cpp:75` | `"\\.\ksapi64_dev"` | `"\\\\.\\ksapi64_dev"` |
| `src/exploits/libwasys/libwasys.cpp:75` | `"\\.\WasysControl"` | `"\\\\.\\WasysControl"` |
| `src/exploits/monprocessex/monprocessex.cpp:75` | `"\\.\MonProcessEX"` | `"\\\\.\\MonProcessEX"` |
| `src/exploits/procexp1702/procexp1702.cpp:562` | `"\\.\PROCEXP152"` | `"\\\\.\\PROCEXP152"` |
| `src/exploits/sysdrv3s/sysdrv3s.cpp:182` | `"\\.\SysDrv3S;\\.\SysDrv3Sxx"` | `"\\\\.\\SysDrv3S;\\\\.\\SysDrv3Sxx"` |
| `src/exploits/wnbios/wnbios.cpp:182` | `"\\.\WNBIOS"` | `"\\\\.\\WNBIOS"` |
| `src/exploits/netease_neacsafe/netease_neacsafe.cpp:671` | `"\\OWNeacSafePort"` | inspect intended path (`\\.\...`) |

Expected matrix impact: these will be reported as `device-open-failed`. Fixing
them converts them to at least "device opened" (primitive verdict then depends
on Defect B).

Recommendation: also change `scripts/new-exploit.ps1` so `-Device` accepts the
Win32 form and writes the C++-escaped literal (single shared-file change
prevents the whole class).

## 3. Defect B — ASRock variants that DO open fail the primitive

For the five "RWE clone" variants the device opened (no device-open-failed
classification) but `kdu exploits test` reported
`cannot read ntoskrnl image header`. Static check of the *shipped blobs* (the
same bytes that were signed and pushed):

| id | driver | sha256(12) | dispatch handler | read case | write case |
| --- | --- | --- | --- | --- | --- |
| asr_autochkupd | AsrAutoChkUpdDrv.sys | 2AA1B08F47FB | 0x110A8 | 0x11228 | 0x1119C |
| asr_ibdrv | dataset_RwDrv.sys | 3C5BF92C2639 | 0x110D4 | 0x11254 | 0x111C8 |
| asr_omgdrv | AsrOmgDrv.sys | 950A4C0C7720 | 0x110A8 | 0x11228 | 0x1119C |
| asr_rapidstart | AsrRapidStartDrv.sys | 0AAFA9F47ACF | 0x1106C | 0x111EC | 0x11160 |
| asrdrv10 | AsrDrv10.sys | ECE0A900EA08 | 0x110A8 | 0x11228 | 0x1119C |

All five dispatch exactly `0x00222808` (read) and `0x0022280C` (write) and use
the same request layout that `asrock.cpp` uses and that was already verified for
AsrDrv107n:

```
struct ASR_RWE_REQUEST {        // 24 bytes, METHOD_BUFFERED
    u64 physical_address;      // +0x00
    u32 size;                  // +0x08   (bytes)
    u32 granularity;           // +0x0C   0=byte, 1=word, 2=dword
    void* data;                // +0x10   user buffer
};
```

Read path (`0x11228` / `0x111EC` / `0x11254`, identical):
`MmMapIoSpace([rsi], [rsi+8])` -> copy `[rsi+8]` bytes from mapping to
`[rsi+0x10]` with width `[rsi+0xC]` -> unmap. Write path is the mirror.
The modules' `read_physical`/`write_physical` are byte-for-byte the same
strategy as the green `asrock.cpp` (page-base mapping + staging copy).

Conclusion: **the ASRock request translation is correct**; the failure is
downstream of the driver (or shared behind it). Supporting evidence: the very
same symptom hits `asrock` itself and `astra64` in the same run, i.e. modules
that were not changed in wave-2A.

## 4. Next steps (for impl-a / Lead)

1. Apply the Defect A fixes; re-run those ids (`--ids` list is resumable).
2. For Defect B, get the hidden error instead of the generic message:
   `run-test.cmd` currently runs `kdu.exe exploits test %1`; the CLI masks the
   underlying `Result` error. Run one id with tracing on (no code change):
   `C:\byovd\kdu.exe --log-level trace --exploit asrock exploits test asrock`
   This prints `DriverKernelAccess`/exploit `KDU_LOG_TRACE` lines, which will
   show whether `find_pml4_from_low_stub` or the walker read failed, and at
   which physical address.
3. If `asrock` fails identically, bisect the shared path: the two recent
   shared changes are the low-stub 8-byte probe (`src/core/low_stub.cpp`) and
   the `page_walks_safe()` gate (`driver_kernel_access.cpp`). The gate is
   inactive for these drivers (`unsafe_physical_holes == false`), so the probe
   is the prime suspect: try a build with the probe forcing a full 0x1000 read
   for one driver to see if the PML4 appears.
4. If `asrock` passes but the five clones fail, the difference is in the
   exploit chunking (all five use `preferred_transfer_chunk() == 0x1000` and
   map at most one page, `asrock` maps up to 0x10000); compare against
   `asrock.cpp` by temporarily setting the clone's chunk to 0x10000.
5. `ktapi` (physical_read + map_physical) PASSED in `docs/lab/20261022-smoke`
   with an earlier binary; keep it in the re-run set as the control for "does
   the physical->VA path work at all".

## 4b. Update after id 30/110 — it is NOT a blanket physical-path failure

As the matrix advanced, two physical-only modules PASSED, both map-style:
`atszio64` (physical_read|physical_write|map_physical) and `cormem` (same), and
in the earlier smoke run `ktapi` (same caps) also passed. Failing physical
modules so far: `asrock`, `axtudrv`, `astra64`, `alcpu`, `aida64`,
`appshopdrv103`, `amd_affdriver`, and the five ASRock RWE clones.

`unsafe_physical_holes` is unset (=false) in every one of those files, so the
WinRing0 opt-in gate (`page_walks_safe()`) is not the discriminator.

Remaining discriminator candidates between pass and fail sets:

* driver copies through a user pointer supplied in the request (RWE family:
  asrock/axtudrv/asr_*) vs the driver returns a user-mode mapping that the
  exploit memcpy's (atszio64/cormem/ktapi). `astra64` is map-style and still
  fails, so this alone does not explain it.
* the map/window request details (window size, Size field, granularity) of the
  failing modules return wrong data or an error on this guest, which the
  self-test reports as a generic header-read failure.

The `--log-level trace` one-shot will show whether `find_pml4_from_low_stub`
finds CR3 and which `read_physical` call first fails, which immediately
separates "PML4 discovery" from "walker read" failures.

## 5. Note on the harness

`scripts/vm-lab.ps1 -All -TestSigning` is resumable and merges `matrix.json`;
the failure rows already carry `classification` (`device-open-failed` vs
`primitive-failed`) which is exactly the split used above. No crash was
observed in this slice (all rows `power=on`, empty `crash_stop_code`).
