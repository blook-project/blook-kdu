# blook-kdu

Self-contained Windows kernel driver exploitation toolkit with a real user-mode
SDK, a manual mapper, an embedded kernel payload and a modern CLI.

> **Authorized security testing and research only.** blook-kdu loads signed but
> vulnerable third-party drivers, gains kernel memory access and maps its own
> payload. Running it on machines you do not own or are not explicitly allowed to
> test is illegal in most jurisdictions and may break the system. The authors
> take no responsibility for misuse.

## What it does

- **Exploits**: **140 bundled vulnerable-driver exploits** (118 memory
  primitives + 22 kill-only process terminators), one independent module and one
  independent CI test job each. Every exploit is compiled into its own static
  library, exposes a metadata record (target driver, CVE, service/device names,
  required OS builds, capabilities) and talks to its driver only through the
  abstract `IDeviceIo`/`IDriverInterface` interfaces. The catalogue spans
  classic KDU-era hardware-access drivers, recent BYOVD CVEs (2023-2026) and
  undocumented drivers (`ktapi`, `truesight`, `astra64`, `winhwdrv`, ...).
- **Kill-only drivers**: 22 exploits expose only a process-termination
  primitive (`Capability::process_kill`, e.g. recent PPL/EDR killers). They are
  driven by `kdu process kill --pid <pid> --exploit <id>` and are reported as
  `SKIP` by `kdu exploits test` (the memory self-test does not apply).
- **Verified usable**: **50 of the 140 exploits are verified usable in the
  signed VMware lab guest** (Windows 11 build 26200, test signing on, blocklist
  off): 36 memory-primitive drivers pass `kdu exploits test` and 14 kill-only
  drivers terminated a PPL-protected process through `kdu process kill`. The
  per-id PASS lists, environment and the documented not-usable-in-this-guest
  drivers (unsafe-physical, RWE, driver access checks, revoked originals,
  hardware-gated PnP) are in
  [docs/lab/RELEASE-VERIFICATION.md](docs/lab/RELEASE-VERIFICATION.md); the 19
  variants added after the lab matrix are unit-tested against mock devices but
  not yet lab-verified.
- **Kernel memory**: physical read/write, kernel virtual read/write, arbitrary
  process read/write (CR3 page-table walk + physical copy, the `mref.cc`
  technique) with best-effort handling of swapped/decoy CR3s.
- **Manual mapping**: maps an arbitrary x64 `.sys` image from memory into the
  kernel without the service manager, without temp files for the payload and
  without a driver object. Relocations, imports, the entry point and the
  optional bootstrap block (used by blook-kchannel) are handled.
- **Kernel payload**: [blook-drv-lite](https://github.com/blook-project/blook-drv-lite)
  compiled into the toolkit, serving the complete memory/process/DSE/handle API
  over [blook-kchannel](https://github.com/blook-project/blook-kchannel)
  (authenticated, encrypted shared-memory IPC - no device objects, no registry).
  It loads through the manual mapper or, on builds where mapped images cannot
  execute, through a signed service (`Parameters\Bootstrap`); `kdu payload load`
  runs it standalone.
- **DSE control**: locate `g_CiOptions` in `ci.dll` without symbols, disable /
  restore driver signature enforcement.
- **Introspection**: kernel module enumeration, driver dumping (from kernel
  memory or from disk).
- **Cleanup**: every driver the toolkit loads is unloaded automatically; the
  service, its registry key and the staged `.sys` file are removed, and a trace
  scanner reports what cannot be removed (System event log records).
- **CLI**: colored tables, hexdumps, `--json` for scripting.

## Quick start

Requirements: Windows 10/11 x64, elevated shell, [xmake](https://xmake.io) 3.x,
a blook-kchannel checkout, a blook-drv-lite checkout and (for the payload) the
WDK.

```powershell
# build (payload + CLI + tests)
git clone https://github.com/blook-project/blook-kchannel ..\blook-kchannel
pwsh scripts/build.ps1 -KchannelDir ..\blook-kchannel
# equivalent manual steps:
#   xmake f -y -m release --kchannel_dir=..\blook-kchannel --wdk="<WDK root>"
#   xmake -y

# list exploits and their target drivers
kdu.exe exploits list

# load the vulnerable driver, map the payload, verify kernel access
kdu.exe info
kdu.exe exploits test gdrv

# self-test every memory exploit in one go (kill-only drivers report SKIP)
kdu.exe exploits test

# use a kill-only exploit (recent PPL/EDR terminators, no memory primitive)
kdu.exe process kill --pid 4242 --exploit pctcore64

# kernel memory
kdu.exe mem virt read 0xFFFFF80000000000 64
kdu.exe mem phys dump 0x1000 4096 -o page.bin
kdu.exe mem process read --pid 1234 0x7FF7A0000000 32

# DSE, modules, driver dumping
kdu.exe dse status
kdu.exe dse disable
kdu.exe modules
kdu.exe dump-driver ntoskrnl.exe -o ntoskrnl.bin

# cleanup (also happens automatically when the process exits)
kdu.exe cleanup --event-log
kdu.exe traces
```

Without an explicit `--exploit <id>` the SDK probes the compiled-in exploits in
order and uses the first one that can load its driver. `--driver-only` skips the
payload and uses a user-mode page-table-walk backend.

## Exploit catalogue and verification

`kdu exploits list` prints the full catalogue with driver file, vendor, CVE and
capabilities. `kdu exploits test [id]` loads each memory exploit's driver,
opens its device, reads the `ntoskrnl` image header through the driver and
unloads everything again. When a driver exposes only a process-termination
primitive the command prints `SKIP <id> kill-only driver (no memory primitive;
self-test N/A)` and does not count it as a failure.

The repository ships a VM lab that rebuilds this matrix against real drivers in
a disposable VMware guest (`bvmenv`):

```powershell
pwsh scripts/vm-lab.ps1 -All -TestSigning -Out docs/lab/<date>
# -> matrix.json / matrix.md / raw/<id>.log, per-id PASS/FAIL/CRASH
```

The lab re-signs driver copies for test signing and drives them through
`BLOOK_KDU_DRIVER_DIR`; the committed evidence under `docs/lab/` is produced by
that script. `docs/adding-exploits.md` documents how to add a driver, and
`tools/driver-intel` statically recovers device names, IRP dispatch and IOCTL
codes from a binary (pefile + capstone, no IDA) including a corpus ranking.

Environment overrides:

| Variable | Meaning |
| --- | --- |
| `BLOOK_KDU_DRIVER_DIR` | load `<dir>\<driver_file>` instead of the embedded RCDATA image (lab / newer vendor build) |
| `BLOOK_KDU_ALLOW_UNSAFE_PHYSICAL=1` | enable page-table based VA/process access for WinRing0-family drivers whose failed `MmMapIoSpace` is dereferenced (may bugcheck; disposable VMs only) |


## Repository layout

```
include/blook/kdu/     public SDK (kdu.h, types.h, version.h)
src/core/              Win32/service/PE/page-table/trace utilities
src/exploits/common/   IExploit/IDriverInterface/IKernelAccess plumbing
src/exploits/<name>/   one exploit per directory (+ embedded driver data)
src/loader/            manual mapper (image preparation + kernel stage)
src/ipc/               blook-kchannel adapter + payload kernel access
src/payload/           manually-mapped kernel payload driver
src/sdk/               public API implementation
src/cli/               CLI11-based CLI
tests/unit/            host unit tests (doctest), per-exploit test binaries
tests/e2e/             bvmenv-driven VM end-to-end runner
tests/guest/           test drivers used inside the VM
scripts/               build/signing/registry/e2e scripts
docs/                  architecture, exploits, e2e and evidence
```

Real VM evidence (Windows 11 26200, 28 checks / 0 failed / 10 documented skips) lives in
[docs/evidence/20261021-e2e-vm](docs/evidence/20261021-e2e-vm/README.md).

See [docs/architecture.md](docs/architecture.md), [docs/exploits.md](docs/exploits.md),
[docs/api.md](docs/api.md) (SDK guide + 20-line example),
[docs/json-schema.md](docs/json-schema.md) (`--json` schema + exit codes) and
[docs/e2e.md](docs/e2e.md).

## Building

The full build requires real blook-kchannel sources (no IPC stubs are supported
for driver/payload builds) and the WDK for the kernel payload:

```powershell
xmake f -y -m release --kchannel_dir=<blook-kchannel> --wdk="<Kits>\10"
xmake -y
xmake run kdu_tests                    # host unit tests
xmake run kdu_exploit_test_gdrv        # one exploit's tests, in isolation
```

CI pins `KCHANNEL_COMMIT` and installs the WDK from the NuGet content package
(see `docs/CI-WDK.md` in `blook-project/blook-xmake-repo`). If the kchannel
sources are missing the payload/IPC/SDK/CLI targets are skipped and a warning is
printed; CI fails on purpose in that case.

## Per-exploit CI

Every exploit has its own job (matrix generated by `scripts/list-exploits.ps1`
from the directory layout), which builds and runs only that exploit's test
binary (`kdu_exploit_test_<name>`). Exploits never share mutable state and are
testable with mocked `IDeviceIo`/`IServiceHost` objects, so CI needs no kernel,
driver or VM for them.

## Safety

Kernel exploitation and manual mapping can hang or bugcheck the machine they run
on. blook-kdu does **not** restrict where it runs: `kdu_open()` only requires the
privileges needed to load a kernel driver. There is no host-mode switch and no
hypervisor check — run it on a disposable VM or a machine you own and can
reboot.

- Host-side unit tests only exercise pure user-mode logic (page tables, PE
  parsing, IOCTL encoding, mocks) and never load a driver.
- The committed e2e evidence is produced through `bvmenv` (see
  `docs/e2e.md` and `docs/lab/`); `scripts/e2e.ps1` takes `-Vm <name>` and every
  `bvmenv` call has a hard timeout. That harness choice does not gate the SDK.
- `kdu doctor` reports the detected hypervisor for information only.
- WinRing0-family drivers (`winring0`, `winhwdrv`, `hwrwdrv`, ...) keep their
  native physical read/write primitive, but page-table based VA/process access is
  opt-in with `BLOOK_KDU_ALLOW_UNSAFE_PHYSICAL=1` because that family dereferences
  a failed `MmMapIoSpace` and can hang or bugcheck the machine. Use it only on a
  disposable VM.
- The VM lab (`scripts/vm-lab.ps1`) re-signs driver copies with the bundled test
  certificate and enables guest test signing: that is a lab-only configuration
  for verifying primitives, not a production signing recommendation. The
  committed embedded drivers are the vendor images, byte-for-byte.
## Safety / legal

- Loads known-vulnerable signed drivers that may be blocked by HVCI, Memory
  Integrity, Secure Boot or a blacklist on your system.
- Kernel memory access can blue-screen the machine if misused; the bundled
  payload validates every request, the SDK validates ranges and sizes.
- Manual mapping patches executable kernel pages: drivers that cannot unload or
  systems with HVCI enabled are unsupported.
- The tool is honest about residual traces: see `kdu doctor --traces` and
  `docs/e2e.md`.

## License

MIT, see [LICENSE](LICENSE).






