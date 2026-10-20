// blook-kdu: public SDK types.
//
// This header has no dependency on any internal blook-kdu header and can be
// consumed by user-mode applications standalone.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace blook::kdu {

// ---------------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------------
//
// Status codes are stable and intended for programmatic handling. Every API
// entry point returns either a value or an Error carrying one of these codes
// plus a human readable message.
enum class Status : int32_t {
    ok = 0,

    // generic
    invalid_argument = 1,
    not_found = 2,
    access_denied = 3,
    not_supported = 4,
    io_error = 5,
    timeout = 6,
    busy = 7,
    already_exists = 8,
    no_memory = 9,
    cancelled = 10,
    internal_error = 11,
    unknown = 12,

    // driver loading / exploits
    invalid_image = 20,
    driver_load_failed = 21,
    driver_not_loaded = 22,
    service_error = 23,
    no_suitable_exploit = 24,
    exploit_probe_failed = 25,
    kernel_access_error = 26,

    // manual mapping
    mapping_failed = 30,
    entry_point_failed = 31,
    unmapping_failed = 32,

    // payload / ipc
    payload_unavailable = 40,
    payload_not_mapped = 41,
    protocol_error = 42,
    auth_failed = 43,

    // memory operations
    address_translation_failed = 50,
    partial_read = 51,
    partial_write = 52,
    invalid_physical_address = 53,

    // DSE
    dse_not_found = 60,
    dse_patch_failed = 61,
};

constexpr const char* status_to_string(Status status) noexcept {
    switch (status) {
        case Status::ok:
            return "ok";
        case Status::invalid_argument:
            return "invalid_argument";
        case Status::not_found:
            return "not_found";
        case Status::access_denied:
            return "access_denied";
        case Status::not_supported:
            return "not_supported";
        case Status::io_error:
            return "io_error";
        case Status::timeout:
            return "timeout";
        case Status::busy:
            return "busy";
        case Status::already_exists:
            return "already_exists";
        case Status::no_memory:
            return "no_memory";
        case Status::cancelled:
            return "cancelled";
        case Status::internal_error:
            return "internal_error";
        case Status::unknown:
            return "unknown";
        case Status::invalid_image:
            return "invalid_image";
        case Status::driver_load_failed:
            return "driver_load_failed";
        case Status::driver_not_loaded:
            return "driver_not_loaded";
        case Status::service_error:
            return "service_error";
        case Status::no_suitable_exploit:
            return "no_suitable_exploit";
        case Status::exploit_probe_failed:
            return "exploit_probe_failed";
        case Status::kernel_access_error:
            return "kernel_access_error";
        case Status::mapping_failed:
            return "mapping_failed";
        case Status::entry_point_failed:
            return "entry_point_failed";
        case Status::unmapping_failed:
            return "unmapping_failed";
        case Status::payload_unavailable:
            return "payload_unavailable";
        case Status::payload_not_mapped:
            return "payload_not_mapped";
        case Status::protocol_error:
            return "protocol_error";
        case Status::auth_failed:
            return "auth_failed";
        case Status::address_translation_failed:
            return "address_translation_failed";
        case Status::partial_read:
            return "partial_read";
        case Status::partial_write:
            return "partial_write";
        case Status::invalid_physical_address:
            return "invalid_physical_address";
        case Status::dse_not_found:
            return "dse_not_found";
        case Status::dse_patch_failed:
            return "dse_patch_failed";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// Error / Result
// ---------------------------------------------------------------------------

struct Error {
    Status code = Status::internal_error;
    std::string message;

    Error() = default;
    Error(Status status, std::string text)
        : code(status), message(std::move(text)) {}
    explicit Error(Status status) : code(status) {}

    [[nodiscard]] bool operator==(Status other) const noexcept {
        return code == other;
    }
};

// A tiny expected-like type so the public SDK stays C++20 compatible.
template <typename T>
class Result {
   public:
    using value_type = T;

    Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}
    Result(Error error) : storage_(std::in_place_index<1>, std::move(error)) {}
    Result(Status status) : storage_(std::in_place_index<1>, Error{status}) {}

    static Result ok(T value) { return Result(std::move(value)); }
    static Result fail(Status status, std::string message = {}) {
        return Result(Error{status, std::move(message)});
    }

    [[nodiscard]] bool has_value() const noexcept {
        return storage_.index() == 0;
    }
    explicit operator bool() const noexcept { return has_value(); }

    T& value() & { return std::get<0>(storage_); }
    const T& value() const& { return std::get<0>(storage_); }
    T&& value() && { return std::get<0>(std::move(storage_)); }

    T* operator->() { return &std::get<0>(storage_); }
    const T* operator->() const { return &std::get<0>(storage_); }
    T& operator*() & { return std::get<0>(storage_); }
    const T& operator*() const& { return std::get<0>(storage_); }

    const Error& error() const& { return std::get<1>(storage_); }
    Error& error() & { return std::get<1>(storage_); }

    Status status() const noexcept {
        return has_value() ? Status::ok : error().code;
    }

    T value_or(T fallback) const {
        return has_value() ? value() : std::move(fallback);
    }

   private:
    std::variant<T, Error> storage_;
};

template <>
class Result<void> {
   public:
    Result() = default;
    Result(Error error) : error_(std::move(error)), ok_(false) {}
    Result(Status status) : error_(status), ok_(false) {}

    static Result ok() { return Result(); }
    static Result fail(Status status, std::string message = {}) {
        return Result(Error{status, std::move(message)});
    }

    [[nodiscard]] bool has_value() const noexcept { return ok_; }
    explicit operator bool() const noexcept { return has_value(); }

    const Error& error() const& { return error_; }
    Error& error() & { return error_; }
    Status status() const noexcept { return ok_ ? Status::ok : error_.code; }

   private:
    Error error_{};
    bool ok_ = true;
};

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

// A kernel module as reported by the loader.
struct ModuleInfo {
    std::string name;   // e.g. "ntoskrnl.exe"
    std::string path;   // e.g. "\\SystemRoot\\system32\\ntoskrnl.exe"
    uint64_t base = 0;  // load address
    uint64_t size = 0;  // SizeOfImage
};

// Device Guard / DSE state.
struct DseState {
    bool enabled = false;          // true when CI enforces signature checks
    uint32_t options = 0;          // current g_CiOptions value
    uint64_t options_address = 0;  // kernel VA of the options DWORD
};

// Process handle reference used by process memory helpers.
struct ProcessTarget {
    uint32_t pid = 0;
    std::string image_name;  // optional, for diagnostics
};

// One trace left behind by driver loading (service/registry/file/event log).
struct TraceFinding {
    std::string category;  // "service", "registry", "file", "eventlog"
    std::string description;
    std::string location;  // path / key / event id
    bool cleaned = false;
};

struct TraceReport {
    std::vector<TraceFinding> findings;

    [[nodiscard]] bool clean() const noexcept {
        for (const auto& finding : findings) {
            if (!finding.cleaned) {
                return false;
            }
        }
        return true;
    }
};

// Report produced by kdu_cleanup()/Session::cleanup().
struct CleanupReport {
    std::vector<std::string> actions;    // performed cleanup steps
    std::vector<std::string> residuals;  // traces that may remain
    bool clean = true;
};

}  // namespace blook::kdu
