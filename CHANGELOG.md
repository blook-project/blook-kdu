# Changelog

All notable changes to blook-kdu are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
