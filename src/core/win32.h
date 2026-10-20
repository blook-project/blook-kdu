// blook-kdu: Windows helpers (handles, services, strings, privileges).
#pragma once

#include <windows.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "blook/kdu/types.h"

namespace blook::kdu::core {

// ---------------------------------------------------------------------------
// String conversion
// ---------------------------------------------------------------------------
std::string to_utf8(std::wstring_view text);
std::wstring to_utf16(std::string_view text);

// Format the current Win32 error as "message (0xXXXX)".
std::string format_win32_error(DWORD error);
// Format an NTSTATUS value.
std::string format_nt_status(LONG status);
Status win32_status(DWORD error);
Status nt_status_status(LONG status);

// ---------------------------------------------------------------------------
// RAII handle
// ---------------------------------------------------------------------------
class UniqueHandle {
   public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~UniqueHandle() { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] bool valid() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }
    explicit operator bool() const noexcept { return valid(); }
    [[nodiscard]] HANDLE release() noexcept {
        return std::exchange(handle_, nullptr);
    }
    void reset(HANDLE handle = nullptr) noexcept {
        if (valid()) {
            ::CloseHandle(handle_);
        }
        handle_ = handle;
    }

   private:
    HANDLE handle_ = nullptr;
};

// ---------------------------------------------------------------------------
// Process / system information
// ---------------------------------------------------------------------------
uint32_t windows_build_number();
std::string windows_version_string();
bool is_windows_64bit();
bool is_process_elevated();
std::string current_process_path();
std::string system_root();

// Enable a privilege on the current process token (e.g. SE_LOAD_DRIVER_NAME).
Result<void> enable_privilege(const wchar_t* name);

// Enable SeDebugPrivilege + SeLoadDriverPrivilege; failures are reported but
// the caller usually wants to continue anyway (the service host may still work
// when running elevated).
Result<void> enable_required_privileges();

// ---------------------------------------------------------------------------
// Service manager
// ---------------------------------------------------------------------------
class ServiceHandle {
   public:
    ServiceHandle() noexcept = default;
    explicit ServiceHandle(SC_HANDLE handle) noexcept : handle_(handle) {}
    ~ServiceHandle() { reset(); }

    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;
    ServiceHandle(ServiceHandle&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)) {}
    ServiceHandle& operator=(ServiceHandle&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    [[nodiscard]] SC_HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] bool valid() const noexcept { return handle_ != nullptr; }
    explicit operator bool() const noexcept { return valid(); }
    void reset(SC_HANDLE handle = nullptr) noexcept {
        if (handle_) {
            ::CloseServiceHandle(handle_);
        }
        handle_ = handle;
    }

   private:
    SC_HANDLE handle_ = nullptr;
};

// Thin wrappers mapped to kdu::Status so callers never have to juggle Win32
// error codes directly.
struct ServiceState {
    DWORD state = 0;  // SERVICE_STOPPED / RUNNING / ...
    DWORD exit_code = 0;
};

class ServiceControl {
   public:
    // Connect to the local SCM (requires elevation for administrative ops).
    static Result<ServiceControl> open();

    ServiceControl() noexcept = default;
    ServiceControl(ServiceControl&&) noexcept = default;
    ServiceControl& operator=(ServiceControl&&) noexcept = default;
    ServiceControl(const ServiceControl&) = delete;
    ServiceControl& operator=(const ServiceControl&) = delete;

    // Create (or open, when it already exists) a kernel driver service.
    Result<void> create_driver(std::wstring_view name,
                               std::wstring_view binary_path);
    Result<void> start(std::wstring_view name);
    Result<void> stop(std::wstring_view name);
    Result<void> remove(std::wstring_view name);
    Result<ServiceState> query(std::wstring_view name);
    Result<bool> exists(std::wstring_view name);

    [[nodiscard]] SC_HANDLE get() const noexcept { return manager_.get(); }

   private:
    explicit ServiceControl(ServiceHandle manager)
        : manager_(std::move(manager)) {}

    Result<ServiceHandle> open_service(DWORD access,
                                       std::wstring_view name) const;

    ServiceHandle manager_;
};

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------
Result<void> write_file(const std::string& path, const void* data, size_t size);
Result<std::vector<uint8_t>> read_file(const std::string& path);
Result<void> remove_file(const std::string& path);
bool file_exists(const std::string& path);

// Create a unique temporary path (does not create the file).
std::string make_temp_path(std::string_view prefix, std::string_view suffix);

}  // namespace blook::kdu::core
