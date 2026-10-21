# blook-kdu

Self-contained Windows kernel driver exploitation toolkit with a real user-mode
SDK, a manual mapper, an embedded kernel payload and a modern CLI.

> **Authorized security testing and research only.** blook-kdu loads signed but
> vulnerable third-party drivers, gains kernel memory access and maps its own
> payload. Running it on machines you do not own or are not explicitly allowed to
> test is illegal in most jurisdictions and may break the system. The authors
> take no responsibility for misuse.

## What it does

- **Exploits**: bundled vulnerable-driver exploits, one independent module and
  one independent CI test job each. Every exploit is compiled into its own
  static library, exposes a metadata record (target driver, CVE, service/device
  names, required OS builds, capabilities) and talks to its driver only through
  the abstract `IDeviceIo`/`IDriverInterface` interfaces.
- **Kernel memory**: physical read/write, kernel virtual read/write, arbitrary
  process read/write (CR3 page-table walk + physical copy, the `mref.cc`
  technique) with best-effort handling of swapped/decoy CR3s.
- **Manual mapping**: maps an arbitrary x64 `.sys` image from memory into the
  kernel without the service manager, without temp files for the payload and
  without a driver object. Relocations, imports, the entry point and the
  optional bootstrap block (used by blook-kchannel) are handled.
- **Kernel payload**: a small manually-mapped driver that serves the complete
  memory/DSE/module API over [blook-kchannel](https://github.com/blook-project/blook-kchannel)
  (authenticated, encrypted shared-memory IPC - no device objects, no registry).
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
a blook-kchannel checkout and (for the payload) the WDK.

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

## Safety: VM-only kernel execution

Kernel exploitation and manual mapping can hang or bugcheck the machine. blook-kdu
therefore **refuses to load kernel drivers unless it detects a VMware guest**
(which is what `bvmenv` manages) and exits with `access_denied` otherwise. This is
enforced in the SDK (`kdu_open`) and in the guest-side e2e runner, not just in
scripts. There is no host-mode switch.

- Host-side unit tests only exercise pure user-mode logic (page tables, PE
  parsing, IOCTL encoding, mocks) and never load a driver.
- All e2e runs go through `bvmenv` (see `docs/e2e.md`); `scripts/e2e.ps1`
  requires `-Vm <name>` and every `bvmenv` call has a hard timeout.
- If you are porting the tool to another hypervisor, the guard is a one-line
  check in `src/sdk/session.cpp` - do not disable it on a physical host.
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



