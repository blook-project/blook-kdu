# Changelog

All notable changes to blook-kdu are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-21

First release. Highlights:

- Self-contained user-mode CLI + SDK that stages bundled vulnerable drivers,
  optionally follows up with a manual-mapped kernel payload over blook-kchannel
  (pinned `40a5337`), and cleans up the driver/service/registry at exit.
- 8 exploits with per-exploit mock unit tests and independent CI jobs:
  `asrock`, `atszio64`, `dbk64`, `echodrv`, `gdrv`, `physmem64`, `rtcore64`,
  `winring0` (decompressed, Authenticode-stripped and re-signed at build time
  with the bundled test signer).
- Memory: physical and kernel-VA read/write, translation, CR3 process memory
  (mref.cc technique), module enumeration, driver dumping, JSON batch runner.
- DSE status/disable/restore API via `g_CiOptions`, ACPI-style victim-driver
  manual mapper for the payload, blook-kchannel IPC, trace scanning and cleanup.
- Safety: the SDK refuses kernel operations outside a VMware guest; the e2e
  harness refuses non-VMware guests and hard-times every bvmenv call.
- Real VM evidence committed under `docs/evidence/20261021-e2e-vm/`
  (Windows 11 26200): 28 checks, 0 failed, 10 documented skips.

Known limitations on Windows 11 26200 (documented, gated in the e2e suite):

- The mapped payload image cannot execute from kernel pool
  (`ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY`); the mapper stage runs but the
  payload needs a PTE-NX-clear pass or a service+kchannel loading mode.
- Four bundled driver images (`atszio64`, `echodrv`, `gdrv`, `physmem64`) are
  rejected by Microsoft's vulnerable-driver blocklist (CERT_E_REVOKED); they are
  recorded per exploit as platform-blocked.
- `dse/disable` is not exercised by the automated suite on this build (patching
  `g_CiOptions` no longer gates driver loads there).
## [Unreleased]

### Added

- `kdu batch <ops.json>`: one-session, JSON-described multi-operation runner
  (read/write physical/virtual/process, translate, CR3, DSE, modules, sleep)
  with `--continue-on-error` and structured results; documented JSON schema.
- Documented stable CLI exit codes and `--json` output schema
  (`docs/json-schema.md`).
- `examples/api_example.cpp`: 20-line SDK walkthrough, documented in
  `docs/api.md`.
- Manual mapper hardening: /GS security-cookie randomization (detect + patch
  cookie/complement), exception-directory detection, strict import/relocation/
  section bounds validation, and host unit tests for malformed/truncated images
  and cookies.
- VM-only safety gate: the SDK refuses kernel operations outside a VMware guest
  (no override), the guest e2e runner refuses non-VMware guests, and the host e2e
  script requires `-Vm` plus hard timeouts on every `bvmenv` call.
- Six more exploits (asrock AsrDrv107n, winring0, physmem64, dbk64, atszio64,
  echodrv) with per-exploit mock unit tests and automatic per-exploit CI jobs.

- Public SDK (`include/blook/kdu/kdu.h`): session object, status/error type,
  physical/kernel-virtual/process memory access, DSE control, module
  enumeration, driver dumping, payload map/unmap, cleanup and trace scanning.
- Exploit abstraction (`IExploit`, `IDriverInterface`, `IKernelAccess`,
  `IServiceHost`, `IDeviceIo`) with dependency injection for unit tests.
- Exploit registry generated from `src/exploits/*` and per-exploit CI jobs.
- First exploits: GIGABYTE GDRV (CVE-2018-19320) and MSI RTCore64
  (CVE-2019-16098), each with its own embedded, staged-at-runtime driver image.
- Driver loading from memory: embedded RCDATA image, temporary file, service
  create/start, device open, automatic stop/delete/cleanup.
- x64 page-table walker (4 KiB/2 MiB/1 GiB pages), low-stub PML4 discovery,
  CR3-based process memory access with PEB validation (mref.cc technique).
- DSE: symbol-free `g_CiOptions` resolution in `ci.dll`, status/disable/restore.
- Manual mapper: image preparation (sections, imports, relocations), kernel
  stage bootstrap, arbitrary `.sys` mapping and payload bootstrap.
- Kernel payload driver (WDK, C++17, manual-mappable) with the complete RPC
  protocol over blook-kchannel.
- blook-kchannel adapter (single translation unit, source-drop integration).
- CLI (CLI11/fmt/spdlog/nlohmann_json): `info`, `exploits list|probe|test`,
  `mem phys|virt|process read|write|dump`, `map`, `unmap`, `unload-payload`,
  `dse status|disable|restore`, `modules`, `dump-driver`, `doctor`, `traces`,
  `cleanup`, `--json`.
- Unit tests (doctest): page tables, EPROCESS helpers, Win32 helpers, exploit
  metadata/IOCTL encoding per exploit.
- GitHub CI: main build (user + payload with pinned blook-kchannel and WDK),
  host unit tests, clang-format check, registry/version consistency, release
  packaging; per-exploit matrix jobs.
- Release workflow with canonical `blook-kdu-<version>-windows-x64.zip` +
  `.sha256` assets and a package-registry manifest/publish script.


