# Architecture

blook-kdu is split into layers that can be built, tested and reasoned about
independently. Every layer only depends on the layers below it, and the public
API in `include/blook/kdu/kdu.h` depends on none of the internals.

```
+----------------------------- CLI (src/cli) ------------------------------+
| CLI11 commands, tables, hexdump, JSON output                              |
+------------------------------------+--------------------------------------+
|              public SDK (include/blook/kdu + src/sdk)                     |
|  Session, kdu_open/kdu_*, status/errors, DSE, modules, dump, cleanup       |
+----------------+-----------------------------+----------------------------+
|  IKernelAccess  (backend-agnostic kernel memory / process access)         |
|                                                                           |
|  DriverKernelAccess                    PayloadKernelAccess                 |
|  (user-mode page-table walk           (blook-kchannel RPC to the          |
|   on top of driver primitives)          manually-mapped kernel payload)    |
+----------------+-----------------------------+----------------------------+
|  IExploit / IDriverInterface              kdu_payload.sys (WDK, C++17)     |
|  one static library per exploit            physical/virtual/process rw,    |
|  (+ embedded signed driver image)          DSE, module enumeration         |
+----------------+-----------------------------+----------------------------+
|  IServiceHost / IDeviceIo                 ManualMapper (src/loader)        |
|  service create/start/stop, device open    image prep + kernel stage       |
+----------------+-----------------------------+----------------------------+
|  core (src/core): Win32 helpers, service control, PE parsing, page tables, |
|  EPROCESS/PEB discovery, kernel export resolution, trace scanning          |
+---------------------------------------------------------------------------+
```

## Session lifecycle

1. `kdu_open()` picks an exploit (explicit id or first probe that succeeds).
2. `IExploit::open()` stages the embedded driver image to a temporary `.sys`,
   creates and starts a kernel service, opens the device and wraps it in a
   `DeviceIo`. `DriverKernelAccess` turns the driver's weak primitives into the
   full memory API (page-table walker, low-stub PML4 discovery, mref-style
   process memory).
3. With `use_payload` (default) the SDK attaches to blook-kchannel, maps the
   embedded payload through the manual mapper, completes the handshake and
   replaces the backend with `PayloadKernelAccess`. The kernel payload now
   implements the whole memory API in kernel mode.
4. All public operations (`mem`, `dse`, `modules`, `dump-driver`, ...) go through
   `IKernelAccess`, so they behave identically on both backends.
5. On `close()` (or destruction) the payload is detached, the vulnerable driver
   is stopped and deleted, the staged file and registry key are removed, and the
   trace scanner reports what remains (event log entries).

## Exploit model

- `IExploit` owns metadata (`ExploitInfo`) and lifecycle: `probe()`, `open()`,
  `unload()`, `cleanup()`, `map_driver()`.
- `IDriverInterface` exposes the driver's real primitives only (`read_physical`,
  `write_physical`, `read_virtual`, `write_virtual`, `translate`). Anything the
  driver cannot do returns `Status::not_supported`; higher layers emulate.
- `IDeviceIo` is a mockable `DeviceIoControl` connection, `IServiceHost` is a
  mockable service installer. Unit tests inject mocks - no kernel, no VM, no
  elevation - which is why every exploit can run in its own CI job.
- Exploits are self-describing: `src/exploits/<name>/<name>.{h,cpp}` +
  `data/*.bin|.rc` and an entry in the generated registry
  (`scripts/gen-exploit-registry.ps1`, verified in CI).

## Manual mapper

`src/loader`:

1. `prepare_image()` parses and validates the PE, lays headers and sections out
   at their virtual addresses, resolves imports against the loaded ntoskrnl
   export table (read from `%SystemRoot%\System32\ntoskrnl.exe`) and collects
   `IMAGE_REL_BASED_DIR64` relocation offsets.
2. The image is copied into an anonymous shared section; a stage-1 stub is
   written into a spare executable page of an already loaded victim driver and
   its dispatch routine is redirected to the stub.
3. Triggering the driver (`DeviceIoControl`) runs the stub in kernel context in
   the loader thread: it allocates non-paged pool, copies the prepared image,
   applies relocations, calls the image entry point with the bootstrap block
   (used by blook-kchannel), restores the patched pages and resumes the original
   dispatch routine.
4. The pool allocation becomes the mapped driver. Because it has no
   `DRIVER_OBJECT`, there is no registry key, device object or
   `PsLoadedModuleList` entry.

Mapped images cannot be fully unloaded in place: freeing the pool that is
currently executing would bugcheck. `unload_payload()` stops the kchannel server
and detaches; the mapped image itself stays allocated until reboot. This is an
explicit, documented residual.

## blook-kchannel

All kernel<->user communication uses
[blook-kchannel](https://github.com/blook-project/blook-kchannel): authenticated
shared-memory rings, ChaCha20 + HMAC-SHA256, no device objects or registry. The
adapter (`src/ipc/`) is the only user-mode translation unit that includes
kchannel headers; the payload (`src/payload/`) is the only kernel one. The
payload RPC protocol is defined in `src/payload/kdu_ops.h` (opcodes >= 0x8000).

## Traces and cleanup

What a run leaves behind, honestly:

| Artifact | Removed by | Notes |
|---|---|---|
| temporary `.sys` file | `cleanup` | never written to `System32\drivers` |
| service registry key | `cleanup` | also deleted directly if the SCM lags |
| driver service | `cleanup` | stopped first, then deleted |
| System event log 7045/7000/7009 | only `cleanup --event-log` | Windows cannot delete single events; clearing is opt-in |
| mapped payload pool | reboot | cannot be freed while executing |
| patched victim driver pages | restored by the stage-1 stub | verified by re-reading the page |
