// blook-kdu: cleanup and trace scanning implementation.
#include "core/trace.h"

#include <windows.h>
#include <winevt.h>

#include <algorithm>

#include "core/log.h"
#include "core/win32.h"

namespace blook::kdu::core {
namespace {

constexpr wchar_t kServicesKey[] = L"SYSTEM\\CurrentControlSet\\Services\\";

std::wstring service_key_path(std::string_view service_name) {
    return kServicesKey + to_utf16(service_name);
}

// Render an event as XML via EvtRender.
std::wstring render_event_xml(EVT_HANDLE event) {
    DWORD buffer_used = 0;
    DWORD property_count = 0;
    if (::EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &buffer_used,
                    &property_count)) {
        return {};
    }
    if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return {};
    }
    std::wstring xml(buffer_used / sizeof(wchar_t), L'\0');
    if (!::EvtRender(nullptr, event, EvtRenderEventXml,
                     static_cast<DWORD>(xml.size() * sizeof(wchar_t)),
                     xml.data(), &buffer_used, &property_count)) {
        return {};
    }
    xml.resize(wcslen(xml.c_str()));
    return xml;
}

bool contains_ascii_case_insensitive(const std::wstring& haystack,
                                     const std::wstring& needle) {
    if (needle.empty() || haystack.size() < needle.size()) {
        return false;
    }
    std::wstring lower_haystack = haystack;
    std::wstring lower_needle = needle;
    std::transform(lower_haystack.begin(), lower_haystack.end(),
                   lower_haystack.begin(), ::towlower);
    std::transform(lower_needle.begin(), lower_needle.end(),
                   lower_needle.begin(), ::towlower);
    return lower_haystack.find(lower_needle) != std::wstring::npos;
}

}  // namespace

bool service_registry_key_exists(std::string_view service_name) {
    HKEY key = nullptr;
    const std::wstring path = service_key_path(service_name);
    const LONG status =
        ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &key);
    if (key) {
        ::RegCloseKey(key);
    }
    return status == ERROR_SUCCESS;
}

Result<void> delete_service_registry_key(std::string_view service_name) {
    const std::wstring path = service_key_path(service_name);
    if (!service_registry_key_exists(service_name)) {
        return Result<void>::ok();
    }
    const LONG status = ::RegDeleteTreeW(HKEY_LOCAL_MACHINE, path.c_str());
    if (status != ERROR_SUCCESS) {
        return Result<void>::fail(
            win32_status(static_cast<DWORD>(status)),
            "RegDeleteTree(" + std::string(service_name) +
                ") failed: " + format_win32_error(static_cast<DWORD>(status)));
    }
    return Result<void>::ok();
}

Result<void> clear_system_event_log() {
    if (!is_process_elevated()) {
        return Result<void>::fail(Status::access_denied,
                                  "clearing the event log requires elevation");
    }
    // wevtutil is present on every supported Windows build.
    const std::wstring command = L"wevtutil.exe cl System";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    std::wstring mutable_command = command;
    if (!::CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr,
                          FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                          &process)) {
        const DWORD error = ::GetLastError();
        return Result<void>::fail(
            win32_status(error),
            "CreateProcess(wevtutil) failed: " + format_win32_error(error));
    }
    ::WaitForSingleObject(process.hProcess, 15000);
    DWORD exit_code = 1;
    ::GetExitCodeProcess(process.hProcess, &exit_code);
    ::CloseHandle(process.hThread);
    ::CloseHandle(process.hProcess);
    if (exit_code != 0) {
        return Result<void>::fail(Status::io_error,
                                  "wevtutil cl System failed with exit code " +
                                      std::to_string(exit_code));
    }
    return Result<void>::ok();
}

Result<std::size_t> count_service_install_events(
    std::string_view service_name) {
    // EventID 7045 = "a new service was installed in the system".
    const wchar_t* query_xml =
        L"*[System[Provider[@Name='Service Control Manager'] and "
        L"(EventID=7045)]]";
    EVT_HANDLE query =
        ::EvtQuery(nullptr, L"System", query_xml,
                   EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!query) {
        const DWORD error = ::GetLastError();
        return Result<std::size_t>::fail(
            win32_status(error),
            "EvtQuery(System) failed: " + format_win32_error(error));
    }
    const std::wstring needle = to_utf16(service_name);
    std::size_t matches = 0;
    std::size_t scanned = 0;
    EVT_HANDLE events[32] = {};
    DWORD returned = 0;
    constexpr std::size_t kMaxScanned = 10000;
    while (scanned < kMaxScanned &&
           ::EvtNext(query, 32, events, INFINITE, 0, &returned)) {
        for (DWORD index = 0; index < returned; ++index) {
            const std::wstring xml = render_event_xml(events[index]);
            if (!xml.empty() && contains_ascii_case_insensitive(xml, needle)) {
                ++matches;
            }
            ++scanned;
            ::EvtClose(events[index]);
            events[index] = nullptr;
        }
        returned = 0;
    }
    ::EvtClose(query);
    return Result<std::size_t>::ok(matches);
}

Result<TraceReport> scan_traces(const std::vector<std::string>& services,
                                const std::vector<std::string>& files) {
    TraceReport report;
    auto manager = ServiceControl::open();
    for (const auto& service : services) {
        bool service_exists = false;
        if (manager) {
            auto exists = manager->exists(to_utf16(service));
            service_exists = exists && exists.value();
        }
        if (service_exists) {
            report.findings.push_back(TraceFinding{
                "service", "kernel driver service is still installed/running",
                service, false});
        }
        if (service_registry_key_exists(service)) {
            report.findings.push_back(TraceFinding{
                "registry", "service registry key still exists",
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\" + service,
                false});
        }
        auto events = count_service_install_events(service);
        if (events && events.value() > 0) {
            report.findings.push_back(TraceFinding{
                "eventlog",
                std::to_string(events.value()) +
                    " Service Control Manager install event(s) reference the "
                    "driver (selective deletion not supported by Windows)",
                "System log, EventID 7045", false});
        }
    }
    for (const auto& file : files) {
        if (file_exists(file)) {
            report.findings.push_back(TraceFinding{
                "file", "staged driver file still on disk", file, false});
        }
    }
    return Result<TraceReport>::ok(report);
}

}  // namespace blook::kdu::core
