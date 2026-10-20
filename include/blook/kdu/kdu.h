// blook-kdu: public user-mode SDK.
//
// blook-kdu is a self-contained driver-exploitation toolkit. Load a vulnerable
// (but signed) driver through one of the bundled exploits, then use that
// driver's kernel primitives to map a small kernel payload which provides a
// complete kernel memory API: physical / kernel-virtual / per-process (CR3)
// memory access, DSE control, module enumeration and driver dumping.
//
// Typical usage:
//
//   auto session = blook::kdu::kdu_open();
//   if (!session) { /* handle error */ }
//   auto payload = blook::kdu::kdu_map_payload(*session);
//   std::vector<std::uint8_t> bytes;
//   if (auto r = blook::kdu::kdu_read_virtual(*session, address, bytes.data(),
//                                             bytes.size())) { ... }
//
// The same API is used by the bundled CLI. The session owns every resource it
// creates and (by default) tears everything down on destruction: the vulnerable
// driver is unloaded and its service/registry/file traces are removed.
//
// Legal notice: authorized security testing and research only. Running this on
// systems you do not own or are not explicitly allowed to test is illegal.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "types.h"
#include "version.h"

namespace blook::kdu {

// ---------------------------------------------------------------------------
// Options and result structures
// ---------------------------------------------------------------------------

struct OpenOptions {
    // Preferred exploit id (e.g. "gdrv", "rtcore64", "asrock"). An empty value
    // makes the SDK auto-select the first available exploit.
    std::string exploit;

    // Try to map the embedded kernel payload after the vulnerable driver is
    // ready. The payload provides the complete feature set (CR3 process
    // memory, DSE, module enumeration, ...). When this fails the SDK can fall
    // back to a user-mode page-table-walk backend if allow_driver_only is set.
    bool use_payload = true;

    // Allow the driver-only backend, which implements memory access by walking
    // page tables from user mode via the exploit's physical read/write.
    bool allow_driver_only = true;

    // Create/start the kernel service for the vulnerable driver. Set to false
    // to attach to a driver whose service is already loaded and running.
    bool load_driver = true;

    // Unload the vulnerable driver and clean up traces when the session is
    // destroyed or closed.
    bool cleanup_on_close = true;

    // spdlog level name: "trace", "debug", "info", "warn", "error", "off".
    std::string log_level = "warn";

    // Optional path to a JSON log file.
    std::string log_file;
};

struct SessionInfo {
    std::string version;
    std::string exploit;       // selected exploit id
    std::string driver_name;   // driver file name, e.g. "gdrv.sys"
    std::string service_name;  // service key created for it
    std::string backend;       // "payload" or "driver"
    uint32_t windows_build = 0;
    bool payload_mapped = false;
    uint64_t payload_base = 0;
    uint64_t payload_size = 0;
    std::vector<std::string> capabilities;
};

// Parameters for the manual-mapper.
struct MapOptions {
    // Diagnostics only; shown in logs and returned in MappedImage.
    std::string name;

    // Ask the kernel allocator for a specific base. Zero lets the kernel
    // choose the allocation, which is the normal case.
    uint64_t preferred_base = 0;

    // Opaque bytes copied into kernel memory and passed to the image entry
    // point as its first argument. Used for the kchannel bootstrap block.
    std::vector<uint8_t> bootstrap;

    // Invoke the image entry point after mapping (default) or only map it.
    bool call_entry = true;
};

struct MappedImage {
    std::string name;
    uint64_t base = 0;
    uint64_t size = 0;
    int32_t entry_status = 0;  // NTSTATUS of the entry point, if invoked
};

struct DumpOptions {
    // Module name as reported by the kernel loader ("ntoskrnl.exe", "ci.dll")
    // or a full path when from_disk is true.
    std::string module;

    // Read the on-disk file instead of the loaded kernel image.
    bool from_disk = false;
};

struct CleanupOptions {
    bool unload_driver = true;  // stop + delete the vulnerable driver service
    bool remove_service_file = true;  // delete the staged .sys file
    bool remove_registry = true;      // delete leftover service registry keys
    bool clean_event_log = false;  // destructive: clears the whole System log
    bool scan_traces = false;      // run the trace scanner after cleanup
};

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

// A kdu session owns: the vulnerable driver service, the loaded payload (if
// any), and every mapping created through it. It is move-only; use
// kdu_open() to create one.
class Session {
   public:
    Session() noexcept;
    ~Session();

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&& other) noexcept;
    Session& operator=(Session&& other) noexcept;

    // Session metadata (valid until the session is closed).
    [[nodiscard]] const SessionInfo& info() const noexcept;
    [[nodiscard]] bool valid() const noexcept;

    // Explicitly close the session (unload driver + cleanup, as configured).
    // Safe to call multiple times. The destructor calls this automatically.
    Result<CleanupReport> close();

    // ------------------------------------------------------------------
    // Payload and manual mapping
    // ------------------------------------------------------------------

    // Map the embedded kernel payload through the vulnerable driver and attach
    // to it over blook-kchannel. Idempotent: returns the existing mapping.
    Result<MappedImage> map_payload(const MapOptions& options = {});

    // Manual-map an arbitrary kernel image (.sys) from memory. Requires a
    // loaded exploit plus the bundled bootstrap/victim mechanism.
    Result<MappedImage> map_driver(std::span<const std::uint8_t> image,
                                   const MapOptions& options = {});

    // Unmap an image previously returned by map_driver(). The embedded payload
    // is detached with unload_payload() instead.
    Result<void> unmap(std::uint64_t base);

    // Detach from / unload the embedded payload.
    Result<void> unload_payload();

    [[nodiscard]] bool payload_mapped() const noexcept;

    // ------------------------------------------------------------------
    // Kernel memory
    // ------------------------------------------------------------------

    Result<std::size_t> read_physical(std::uint64_t address, void* buffer,
                                      std::size_t size);
    Result<std::size_t> write_physical(std::uint64_t address,
                                       const void* buffer, std::size_t size);

    Result<std::size_t> read_virtual(std::uint64_t address, void* buffer,
                                     std::size_t size);
    Result<std::size_t> write_virtual(std::uint64_t address, const void* buffer,
                                      std::size_t size);

    Result<std::uint64_t> translate_virtual(std::uint64_t address);

    // Convenience wrappers returning owning byte vectors.
    Result<std::vector<std::uint8_t>> read_physical_bytes(std::uint64_t address,
                                                          std::size_t size);
    Result<void> write_physical_bytes(std::uint64_t address,
                                      std::span<const std::uint8_t> bytes);
    Result<std::vector<std::uint8_t>> read_virtual_bytes(std::uint64_t address,
                                                         std::size_t size);
    Result<void> write_virtual_bytes(std::uint64_t address,
                                     std::span<const std::uint8_t> bytes);

    // ------------------------------------------------------------------
    // Process memory (CR3-based page-table walk)
    // ------------------------------------------------------------------

    // CR3 (DirectoryTableBase) of the target process, validated by walking its
    // PEB. Requires the payload backend or a driver backend with physical
    // memory access.
    Result<std::uint64_t> process_cr3(std::uint32_t pid);

    Result<std::size_t> read_process(std::uint32_t pid, std::uint64_t address,
                                     void* buffer, std::size_t size);
    Result<std::size_t> write_process(std::uint32_t pid, std::uint64_t address,
                                      const void* buffer, std::size_t size);

    Result<std::vector<std::uint8_t>> read_process_bytes(std::uint32_t pid,
                                                         std::uint64_t address,
                                                         std::size_t size);
    Result<void> write_process_bytes(std::uint32_t pid, std::uint64_t address,
                                     std::span<const std::uint8_t> bytes);

    // ------------------------------------------------------------------
    // DSE / driver signature enforcement
    // ------------------------------------------------------------------

    Result<DseState> dse_status();
    Result<void> dse_disable();
    Result<void> dse_restore();

    // ------------------------------------------------------------------
    // Introspection
    // ------------------------------------------------------------------

    Result<std::vector<ModuleInfo>> enum_modules();
    Result<ModuleInfo> find_module(std::string_view name);

    // Dump a loaded kernel module's image bytes (reads kernel memory).
    Result<std::vector<std::uint8_t>> dump_driver(const DumpOptions& options);

    // ------------------------------------------------------------------
    // Cleanup / trace scanning
    // ------------------------------------------------------------------

    Result<CleanupReport> cleanup(const CleanupOptions& options = {});
    Result<TraceReport> scan_traces();

   private:
    friend Result<Session> kdu_open(const OpenOptions& options);

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Free-function facade (matches the classic kdu_* API)
// ---------------------------------------------------------------------------

Result<Session> kdu_open(const OpenOptions& options = {});

// Explicitly close a session (same as Session::close()).
Result<CleanupReport> kdu_close(Session& session);

Result<MappedImage> kdu_map_payload(Session& session,
                                    const MapOptions& options = {});
Result<MappedImage> kdu_map_driver(Session& session,
                                   std::span<const std::uint8_t> image,
                                   const MapOptions& options = {});
Result<void> kdu_unmap(Session& session, std::uint64_t base);
Result<void> kdu_unload_payload(Session& session);

Result<std::size_t> kdu_read_physical(Session& session, std::uint64_t address,
                                      void* buffer, std::size_t size);
Result<std::size_t> kdu_write_physical(Session& session, std::uint64_t address,
                                       const void* buffer, std::size_t size);
Result<std::size_t> kdu_read_virtual(Session& session, std::uint64_t address,
                                     void* buffer, std::size_t size);
Result<std::size_t> kdu_write_virtual(Session& session, std::uint64_t address,
                                      const void* buffer, std::size_t size);
Result<std::uint64_t> kdu_translate_virtual(Session& session,
                                            std::uint64_t address);

Result<std::size_t> kdu_read_process(Session& session, std::uint32_t pid,
                                     std::uint64_t address, void* buffer,
                                     std::size_t size);
Result<std::size_t> kdu_write_process(Session& session, std::uint32_t pid,
                                      std::uint64_t address, const void* buffer,
                                      std::size_t size);
Result<std::uint64_t> kdu_process_cr3(Session& session, std::uint32_t pid);

Result<DseState> kdu_dse_status(Session& session);
Result<void> kdu_dse_disable(Session& session);
Result<void> kdu_dse_restore(Session& session);

Result<std::vector<ModuleInfo>> kdu_enum_modules(Session& session);
Result<std::vector<std::uint8_t>> kdu_dump_driver(Session& session,
                                                  const DumpOptions& options);

Result<CleanupReport> kdu_cleanup(Session& session,
                                  const CleanupOptions& options = {});
Result<TraceReport> kdu_scan_traces(Session& session);

}  // namespace blook::kdu
