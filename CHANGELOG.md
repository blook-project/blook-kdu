# Changelog

All notable changes to blook-kdu are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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

