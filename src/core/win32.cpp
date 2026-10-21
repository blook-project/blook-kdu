// blook-kdu: Windows helpers implementation.
#include "core/win32.h"

#include <bcrypt.h>
#include <objbase.h>
#include <psapi.h>
#include <shellapi.h>
#include <winternl.h>
#include <winver.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <cstring>
#include <vector>

namespace blook::kdu::core {
namespace {

constexpr DWORD kServiceWaitMs = 15000;

}  // namespace

// ---------------------------------------------------------------------------
// String conversion
// ---------------------------------------------------------------------------
std::string to_utf8(std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    const int needed = ::WideCharToMultiByte(CP_UTF8, 0, text.data(),
                                             static_cast<int>(text.size()),
                                             nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string result(static_cast<size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text.data(),
                          static_cast<int>(text.size()), result.data(), needed,
                          nullptr, nullptr);
    return result;
}

std::wstring to_utf16(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    const int needed = ::MultiByteToWideChar(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0) {
        return {};
    }
    std::wstring result(static_cast<size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.data(),
                          static_cast<int>(text.size()), result.data(), needed);
    return result;
}

std::string ansi_to_utf8(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    const int wide_length = ::MultiByteToWideChar(
        CP_ACP, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (wide_length <= 0) {
        return std::string(text);
    }
    std::wstring wide(static_cast<std::size_t>(wide_length), L'\0');
    ::MultiByteToWideChar(CP_ACP, 0, text.data(), static_cast<int>(text.size()),
                          wide.data(), wide_length);
    return to_utf8(wide);
}

std::string format_win32_error(DWORD error) {
    char* buffer = nullptr;
    const DWORD length = ::FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0, reinterpret_cast<char*>(&buffer), 0, nullptr);
    std::string message;
    if (length && buffer) {
        message.assign(buffer, length);
        // FormatMessage returns localized ANSI text (e.g. GBK); the SDK emits
        // UTF-8 JSON, so convert it or nlohmann refuses to serialize it.
        message = ansi_to_utf8(message);
        while (!message.empty() &&
               (message.back() == '\r' || message.back() == '\n')) {
            message.pop_back();
        }
    }
    if (buffer) {
        ::LocalFree(buffer);
    }
    char code[32];
    std::snprintf(code, sizeof(code), " (0x%08lX)",
                  static_cast<unsigned long>(error));
    return message + code;
}

std::string format_nt_status(LONG status) {
    char code[32];
    std::snprintf(code, sizeof(code), "0x%08lX",
                  static_cast<unsigned long>(status));
    return code;
}

Status win32_status(DWORD error) {
    switch (error) {
        case ERROR_SUCCESS:
            return Status::ok;
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_SERVICE_DOES_NOT_EXIST:
            return Status::not_found;
        case ERROR_ACCESS_DENIED:
        case ERROR_PRIVILEGE_NOT_HELD:
            return Status::access_denied;
        case ERROR_INVALID_PARAMETER:
            return Status::invalid_argument;
        case ERROR_NOT_ENOUGH_MEMORY:
        case ERROR_OUTOFMEMORY:
            return Status::no_memory;
        case ERROR_SERVICE_ALREADY_RUNNING:
        case ERROR_SERVICE_EXISTS:
            return Status::already_exists;
        case ERROR_SERVICE_NOT_ACTIVE:
            return Status::driver_not_loaded;
        case ERROR_BAD_EXE_FORMAT:
            return Status::invalid_image;
        case ERROR_TIMEOUT:
            return Status::timeout;
        default:
            return Status::io_error;
    }
}

Status nt_status_status(LONG status) {
    if (status == 0) {
        return Status::ok;
    }
    if (status < 0) {
        switch (static_cast<unsigned long>(status)) {
            case 0xC0000022ul:  // STATUS_ACCESS_DENIED
                return Status::access_denied;
            case 0xC0000034ul:  // STATUS_OBJECT_NAME_NOT_FOUND
            case 0xC0000035ul:  // STATUS_OBJECT_NAME_COLLISION
                return Status::not_found;
            case 0xC0000017ul:  // STATUS_NO_MEMORY
                return Status::no_memory;
            case 0xC000000Dul:  // STATUS_INVALID_PARAMETER
                return Status::invalid_argument;
            case 0xC000000Ful:  // STATUS_NO_SUCH_FILE
                return Status::not_found;
            case 0xC0000103ul:  // STATUS_NOT_SUPPORTED
                return Status::not_supported;
            case 0xC0000142ul:  // STATUS_DLL_INIT_FAILED
                return Status::driver_load_failed;
            case 0xC0000225ul:  // STATUS_NOT_FOUND
                return Status::not_found;
            case 0xC0000603ul:  // STATUS_INVALID_IMAGE_HASH
                return Status::invalid_image;
            default:
                break;
        }
    }
    return Status::io_error;
}

// ---------------------------------------------------------------------------
// Process / system information
// ---------------------------------------------------------------------------
uint32_t windows_build_number() {
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return 0;
    }
    const auto fn = reinterpret_cast<RtlGetVersionFn>(
        ::GetProcAddress(ntdll, "RtlGetVersion"));
    if (!fn) {
        return 0;
    }
    RTL_OSVERSIONINFOW info{};
    info.dwOSVersionInfoSize = sizeof(info);
    if (fn(&info) != 0) {
        return 0;
    }
    return info.dwBuildNumber;
}

std::string windows_version_string() {
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return "unknown";
    }
    const auto fn = reinterpret_cast<RtlGetVersionFn>(
        ::GetProcAddress(ntdll, "RtlGetVersion"));
    if (!fn) {
        return "unknown";
    }
    RTL_OSVERSIONINFOW info{};
    info.dwOSVersionInfoSize = sizeof(info);
    if (fn(&info) != 0) {
        return "unknown";
    }
    char buffer[96];
    std::snprintf(buffer, sizeof(buffer), "%lu.%lu.%lu", info.dwMajorVersion,
                  info.dwMinorVersion, info.dwBuildNumber);
    return buffer;
}

bool is_windows_64bit() {
    SYSTEM_INFO info{};
    ::GetNativeSystemInfo(&info);
    return info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
}

bool is_running_under_hypervisor(std::string* vendor) {
    int registers[4] = {0, 0, 0, 0};
    __cpuid(registers, 1);
    const bool hypervisor_bit = (registers[2] & (1 << 31)) != 0;
    if (!hypervisor_bit) {
        return false;
    }
    __cpuid(registers, 0x40000000);
    char name[13] = {};
    std::memcpy(name, &registers[1], 4);
    std::memcpy(name + 4, &registers[2], 4);
    std::memcpy(name + 8, &registers[3], 4);
    if (vendor) {
        *vendor = name;
    }
    return true;
}

std::uint64_t random_u64() {
    std::uint64_t value = 0;
    if (::BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&value),
                          sizeof(value),
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        // Extremely unlikely; fall back to a time-seeded mix so the cookie is
        // still not the linker default.
        value = static_cast<std::uint64_t>(::GetTickCount64()) << 17;
        value ^= ::GetCurrentProcessId();
        value ^= reinterpret_cast<std::uintptr_t>(&value);
    }
    return value | 1;
}

bool is_process_elevated() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    const bool ok = ::GetTokenInformation(token, TokenElevation, &elevation,
                                          size, &size) != FALSE &&
                    elevation.TokenIsElevated != 0;
    ::CloseHandle(token);
    return ok;
}

std::string current_process_path() {
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length = ::GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            return {};
        }
        if (length < buffer.size() - 1) {
            buffer.resize(length);
            return to_utf8(buffer);
        }
        buffer.resize(buffer.size() * 2);
    }
}

std::string system_root() {
    std::wstring buffer(MAX_PATH, L'\0');
    const UINT length =
        ::GetWindowsDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
    if (length == 0 || length >= buffer.size()) {
        return "C:\\Windows";
    }
    buffer.resize(length);
    return to_utf8(buffer);
}

Result<void> enable_privilege(const wchar_t* name) {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(),
                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return Result<void>::fail(
            win32_status(::GetLastError()),
            "OpenProcessToken failed: " + format_win32_error(::GetLastError()));
    }
    LUID luid{};
    if (!::LookupPrivilegeValueW(nullptr, name, &luid)) {
        const DWORD error = ::GetLastError();
        ::CloseHandle(token);
        return Result<void>::fail(
            win32_status(error),
            "LookupPrivilegeValue failed: " + format_win32_error(error));
    }
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!::AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges),
                                 nullptr, nullptr)) {
        const DWORD error = ::GetLastError();
        ::CloseHandle(token);
        return Result<void>::fail(
            win32_status(error),
            "AdjustTokenPrivileges failed: " + format_win32_error(error));
    }
    const DWORD error = ::GetLastError();
    ::CloseHandle(token);
    if (error == ERROR_NOT_ALL_ASSIGNED) {
        return Result<void>::fail(Status::access_denied, "privilege not held");
    }
    return Result<void>::ok();
}

Result<void> enable_required_privileges() {
    const auto debug = enable_privilege(SE_DEBUG_NAME);
    const auto driver = enable_privilege(SE_LOAD_DRIVER_NAME);
    if (!debug && !driver) {
        return Result<void>::fail(
            Status::access_denied,
            "could not enable SeDebugPrivilege or SeLoadDriverPrivilege; "
            "run elevated");
    }
    return Result<void>::ok();
}

// ---------------------------------------------------------------------------
// Service manager
// ---------------------------------------------------------------------------
Result<ServiceControl> ServiceControl::open() {
    SC_HANDLE handle =
        ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!handle) {
        const DWORD error = ::GetLastError();
        return Result<ServiceControl>::fail(
            win32_status(error), "OpenSCManager failed (elevation required): " +
                                     format_win32_error(error));
    }
    return Result<ServiceControl>::ok(ServiceControl(ServiceHandle(handle)));
}

Result<ServiceHandle> ServiceControl::open_service(
    DWORD access, std::wstring_view name) const {
    if (!manager_.valid()) {
        return Result<ServiceHandle>::fail(Status::service_error,
                                           "service manager not open");
    }
    std::wstring name_buffer(name);
    SC_HANDLE handle =
        ::OpenServiceW(manager_.get(), name_buffer.c_str(), access);
    if (!handle) {
        const DWORD error = ::GetLastError();
        return Result<ServiceHandle>::fail(
            win32_status(error),
            "OpenService failed: " + format_win32_error(error));
    }
    return Result<ServiceHandle>::ok(ServiceHandle(handle));
}

Result<void> ServiceControl::create_driver(std::wstring_view name,
                                           std::wstring_view binary_path) {
    std::wstring name_buffer(name);
    // Kernel driver ImagePath is an NT path and must not be quoted; quoting
    // makes the SCM reject it with ERROR_INVALID_NAME on current Windows.
    std::wstring path(binary_path);
    SC_HANDLE handle = ::CreateServiceW(
        manager_.get(), name_buffer.c_str(), name_buffer.c_str(),
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE, path.c_str(), nullptr, nullptr, nullptr, nullptr,
        nullptr);
    if (!handle) {
        const DWORD error = ::GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            return Result<void>::ok();
        }
        return Result<void>::fail(
            win32_status(error),
            "CreateService failed: " + format_win32_error(error));
    }
    ::CloseServiceHandle(handle);
    return Result<void>::ok();
}

Result<void> ServiceControl::start(std::wstring_view name) {
    auto service = open_service(SERVICE_START | SERVICE_QUERY_STATUS, name);
    if (!service) {
        return Result<void>::fail(service.error().code,
                                  service.error().message);
    }
    if (!::StartServiceW(service->get(), 0, nullptr)) {
        const DWORD error = ::GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            return Result<void>::fail(
                win32_status(error),
                "StartService failed: " + format_win32_error(error));
        }
    }
    SERVICE_STATUS status{};
    if (!::QueryServiceStatus(service->get(), &status)) {
        const DWORD error = ::GetLastError();
        return Result<void>::fail(
            win32_status(error),
            "QueryServiceStatus failed: " + format_win32_error(error));
    }
    if (status.dwCurrentState == SERVICE_RUNNING) {
        return Result<void>::ok();
    }
    if (status.dwCurrentState == SERVICE_START_PENDING) {
        return Result<void>::ok();
    }
    return Result<void>::fail(Status::driver_load_failed,
                              "service did not reach running state (state=" +
                                  std::to_string(status.dwCurrentState) + ")");
}

Result<void> ServiceControl::stop(std::wstring_view name) {
    auto service = open_service(SERVICE_STOP | SERVICE_QUERY_STATUS, name);
    if (!service) {
        if (service.error().code == Status::not_found) {
            return Result<void>::ok();
        }
        return Result<void>::fail(service.error().code,
                                  service.error().message);
    }
    SERVICE_STATUS status{};
    if (!::ControlService(service->get(), SERVICE_CONTROL_STOP, &status)) {
        const DWORD error = ::GetLastError();
        if (error != ERROR_SERVICE_NOT_ACTIVE) {
            return Result<void>::fail(
                win32_status(error),
                "ControlService(STOP) failed: " + format_win32_error(error));
        }
    }
    const ULONGLONG deadline = ::GetTickCount64() + kServiceWaitMs;
    for (;;) {
        if (!::QueryServiceStatus(service->get(), &status)) {
            const DWORD error = ::GetLastError();
            if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
                return Result<void>::ok();
            }
            return Result<void>::fail(
                win32_status(error),
                "QueryServiceStatus failed: " + format_win32_error(error));
        }
        if (status.dwCurrentState == SERVICE_STOPPED) {
            return Result<void>::ok();
        }
        if (::GetTickCount64() > deadline) {
            return Result<void>::fail(Status::timeout,
                                      "service stop timed out");
        }
        ::Sleep(50);
    }
}

Result<void> ServiceControl::remove(std::wstring_view name) {
    auto service = open_service(DELETE, name);
    if (!service) {
        if (service.error().code == Status::not_found) {
            return Result<void>::ok();
        }
        return Result<void>::fail(service.error().code,
                                  service.error().message);
    }
    if (!::DeleteService(service->get())) {
        const DWORD error = ::GetLastError();
        if (error != ERROR_SERVICE_MARKED_FOR_DELETE) {
            return Result<void>::fail(
                win32_status(error),
                "DeleteService failed: " + format_win32_error(error));
        }
    }
    return Result<void>::ok();
}

Result<ServiceState> ServiceControl::query(std::wstring_view name) {
    auto service = open_service(SERVICE_QUERY_STATUS, name);
    if (!service) {
        return Result<ServiceState>::fail(service.error().code,
                                          service.error().message);
    }
    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    if (!::QueryServiceStatusEx(service->get(), SC_STATUS_PROCESS_INFO,
                                reinterpret_cast<LPBYTE>(&status),
                                sizeof(status), &needed)) {
        const DWORD error = ::GetLastError();
        return Result<ServiceState>::fail(
            win32_status(error),
            "QueryServiceStatusEx failed: " + format_win32_error(error));
    }
    return Result<ServiceState>::ok(
        ServiceState{status.dwCurrentState, status.dwWin32ExitCode});
}

Result<bool> ServiceControl::exists(std::wstring_view name) {
    auto service = open_service(SERVICE_QUERY_STATUS, name);
    if (service) {
        return Result<bool>::ok(true);
    }
    if (service.error().code == Status::not_found) {
        return Result<bool>::ok(false);
    }
    return Result<bool>::fail(service.error().code, service.error().message);
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------
Result<void> write_file(const std::string& path, const void* data,
                        size_t size) {
    UniqueHandle file(::CreateFileW(to_utf16(path).c_str(), GENERIC_WRITE, 0,
                                    nullptr, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        const DWORD error = ::GetLastError();
        return Result<void>::fail(
            win32_status(error),
            "CreateFile failed: " + format_win32_error(error));
    }
    size_t written = 0;
    while (written < size) {
        DWORD chunk = 0;
        const DWORD want =
            static_cast<DWORD>(std::min<size_t>(size - written, 0x10000000));
        if (!::WriteFile(file.get(),
                         static_cast<const uint8_t*>(data) + written, want,
                         &chunk, nullptr)) {
            const DWORD error = ::GetLastError();
            return Result<void>::fail(
                win32_status(error),
                "WriteFile failed: " + format_win32_error(error));
        }
        written += chunk;
    }
    ::FlushFileBuffers(file.get());
    return Result<void>::ok();
}

Result<std::vector<uint8_t>> read_file(const std::string& path) {
    UniqueHandle file(::CreateFileW(to_utf16(path).c_str(), GENERIC_READ,
                                    FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) {
        const DWORD error = ::GetLastError();
        return Result<std::vector<uint8_t>>::fail(
            win32_status(error),
            "CreateFile failed: " + format_win32_error(error));
    }
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(file.get(), &size) || size.QuadPart < 0) {
        const DWORD error = ::GetLastError();
        return Result<std::vector<uint8_t>>::fail(
            win32_status(error),
            "GetFileSizeEx failed: " + format_win32_error(error));
    }
    std::vector<uint8_t> data(static_cast<size_t>(size.QuadPart));
    if (!data.empty()) {
        DWORD read = 0;
        if (!::ReadFile(file.get(), data.data(),
                        static_cast<DWORD>(data.size()), &read, nullptr)) {
            const DWORD error = ::GetLastError();
            return Result<std::vector<uint8_t>>::fail(
                win32_status(error),
                "ReadFile failed: " + format_win32_error(error));
        }
        data.resize(read);
    }
    return Result<std::vector<uint8_t>>::ok(std::move(data));
}

Result<void> remove_file(const std::string& path) {
    if (!::DeleteFileW(to_utf16(path).c_str())) {
        const DWORD error = ::GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            return Result<void>::ok();
        }
        return Result<void>::fail(
            win32_status(error),
            "DeleteFile failed: " + format_win32_error(error));
    }
    return Result<void>::ok();
}

bool file_exists(const std::string& path) {
    const DWORD attributes = ::GetFileAttributesW(to_utf16(path).c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::wstring kernel_driver_image_path(const std::string& dos_path) {
    std::wstring path = to_utf16(dos_path);
    if (path.size() > 2 && path[1] == L':') {
        return L"\\??\\" + path;
    }
    return path;
}

std::string make_staging_path(std::string_view prefix,
                              std::string_view suffix) {
    std::wstring directory = to_utf16(system_root() + "\\Temp");
    const DWORD attributes = ::GetFileAttributesW(directory.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        return make_temp_path(prefix, suffix);
    }
    GUID guid{};
    ::CoCreateGuid(&guid);
    wchar_t name[96];
    std::swprintf(name, 96, L"\\%hs%08lX-%04X%04X%08lX%hs",
                  std::string(prefix).c_str(),
                  static_cast<unsigned long>(guid.Data1), guid.Data2,
                  guid.Data3, *reinterpret_cast<unsigned long*>(guid.Data4),
                  std::string(suffix).c_str());
    return to_utf8(directory + name);
}

std::string make_temp_path(std::string_view prefix, std::string_view suffix) {
    std::wstring temp(MAX_PATH, L'\0');
    const DWORD length = ::GetTempPathW(MAX_PATH, temp.data());
    temp.resize(length ? length : 0);
    GUID guid{};
    ::CoCreateGuid(&guid);
    wchar_t name[96];
    std::swprintf(name, 96, L"\\%hs%08lX-%04X%04X%08lX%hs",
                  std::string(prefix).c_str(),
                  static_cast<unsigned long>(guid.Data1), guid.Data2,
                  guid.Data3, *reinterpret_cast<unsigned long*>(guid.Data4),
                  std::string(suffix).c_str());
    return to_utf8(temp + name);
}

}  // namespace blook::kdu::core
