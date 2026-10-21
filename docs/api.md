# SDK API guide

`include/blook/kdu/kdu.h` is the only header an application needs. Everything is
in `namespace blook::kdu`, errors are values (`Result<T>` / `Error` /
`Status`), and the session owns every resource it creates (RAII cleanup on
destruction).

## 20-line example

```cpp
#include <windows.h>
#include <cstdio>
#include <blook/kdu/kdu.h>

int main() {
    auto opened = blook::kdu::kdu_open();                 // pick an exploit
    if (!opened) { std::fprintf(stderr, "%s\n", opened.error().message.c_str()); return 1; }
    auto& s = opened.value();
    auto mapped = s.map_payload();                        // map kernel payload
    std::uint8_t buffer[16] = {};
    auto read = s.read_process(GetCurrentProcessId(),
                               (std::uint64_t)buffer, buffer, sizeof buffer);
    if (!read) { std::fprintf(stderr, "%s\n", read.error().message.c_str()); return 1; }
    std::printf("payload@0x%llx backend=%s read=%zu\n",
                (unsigned long long)(mapped ? mapped->base : 0),
                s.info().backend.c_str(), read.value());
    return 0;                                             // auto unload + cleanup
}
```

A compiled copy lives in `examples/api_example.cpp` (`xmake build
kdu_api_example`). Run it inside a bvmenv guest: kernel execution is refused on
physical hosts.

## Lifecycle

1. `kdu_open(OpenOptions)` - probes the compiled-in exploits in order (or uses
   `OpenOptions::exploit`), loads the vulnerable driver as a service, opens the
   device and wraps it in the driver backend.
2. `Session::map_payload(MapOptions)` - optional: attaches blook-kchannel, maps
   the embedded payload through the manual mapper and switches to the payload
   backend (full CR3 process memory, DSE, module enumeration).
3. Use the operations (memory, process, DSE, modules, dump).
4. Destroy the session (or call `kdu_close`/`Session::close`) - payload detached,
   DSE restored if it was changed, driver stopped, service/file/registry
   removed, report in `CleanupReport`.

`Session` is move-only. `map_payload()` is idempotent and returns the existing
mapping when already mapped.

## Operations

| Method | Free function | Backend |
|---|---|---|
| `read_physical/write_physical` | `kdu_read_physical`, ... | driver physical primitive or payload |
| `read_virtual/write_virtual` | `kdu_read_virtual`, ... | kernel VA (native or page-table walk) |
| `translate_virtual` | `kdu_translate_virtual` | page-table walk |
| `read_process/write_process` | `kdu_read_process`, ... | CR3 walk (mref.cc technique) |
| `process_cr3` | `kdu_process_cr3` | KPROCESS.DirectoryTableBase, PEB-validated |
| `dse_status/dse_disable/dse_restore` | `kdu_dse_*` | `g_CiOptions` in ci.dll |
| `enum_modules/find_module` | `kdu_enum_modules` | kernel module list |
| `dump_driver` | `kdu_dump_driver` | loaded image bytes (or `from_disk`) |
| `map_driver/unmap` | `kdu_map_driver`, `kdu_unmap` | manual mapper |
| `map_payload/unload_payload` | `kdu_map_payload`, `kdu_unload_payload` | payload + kchannel |
| `cleanup/scan_traces` | `kdu_cleanup`, `kdu_scan_traces` | service/file/registry/event log |

## Error handling

`Result<T>` is either a value or an `Error { Status code; std::string message; }`.
`Status` values are stable (see `types.h`); `status_to_string()` returns the
canonical name. The CLI maps them to documented exit codes (see README):
`0 ok, 2 usage, 3 access, 4 not found, 5 unsupported, 6 timeout, 10 io,
13 no exploit, 14 mapping, 15 payload`.

Typical recoverable errors: `no_suitable_exploit` (no bundled driver could load),
`access_denied` (not elevated, or host without a hypervisor guard),
`payload_unavailable` (build without blook-kchannel), `address_translation_failed`
(CR3/PTE not present or decoy CR3).

## Backends and capabilities

`SessionInfo::backend` is `driver` or `payload`; `SessionInfo::capabilities`
lists what the active backend can do (`physical_read`, `virtual_write`,
`translate`, ...). Driver-only backends emulate virtual memory with a user-mode
page-table walker when the driver only exposes physical primitives; process
memory needs physical read (or the payload). `map_payload()` needs a
physical-write exploit. The CLI prints the same data via `kdu info --json`.

## Threading / ownership

A `Session` is not thread-safe; serialize calls or use one session per thread.
Buffers are caller-owned; byte-vector shortcuts (`read_*_bytes`) exist for
convenience. Mapped images live in non-paged pool: `unmap()` stops tracking them
but cannot free the executing pool allocation (documented residual, released on
reboot). `unload_payload()` stops the kchannel server and detaches cleanly.
