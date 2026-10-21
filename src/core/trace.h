// blook-kdu: cleanup and trace scanning.
//
// Honest accounting of what a driver-loading toolkit leaves behind:
//   * a temporary .sys file we staged (removable),
//   * a service registry key HKLM\SYSTEM\CurrentControlSet\Services\<name>
//     (removable),
//   * Service Control Manager events in the System event log, notably 7045
//     ("a service was installed") and 7000/7009/7011 load errors (Windows does
//     not expose selective deletion; only clearing the whole log removes them),
//   * the Process Explorer / vulnerable driver image itself if it was loaded
//     from a standard drivers directory (we never do that: we always stage a
//     temp file).
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "blook/kdu/types.h"

namespace blook::kdu::core {

// Delete HKLM\SYSTEM\CurrentControlSet\Services\<service> if it exists.
Result<void> delete_service_registry_key(std::string_view service_name);

// True when the service registry key exists.
bool service_registry_key_exists(std::string_view service_name);

// Clear the System event log (destructive; requires elevation).
Result<void> clear_system_event_log();

// Count System event log events that reference the given service/driver name
// (EventID 7045 "service installed"). Read-only.
Result<std::size_t> count_service_install_events(std::string_view service_name);

// Persistent record of drivers staged by blook-kdu. Used by `kdu traces` /
// `kdu doctor --traces` in a *later* process (after the session that loaded the
// driver is gone) so the scan is not blind.
void remember_staged_driver(std::string_view service, std::string_view path);
void forget_staged_driver(std::string_view service);
struct RememberedDriver {
    std::string service;
    std::string path;
};
std::vector<RememberedDriver> remembered_drivers();

// Scan for every trace left by the given service names and staged files.
Result<TraceReport> scan_traces(const std::vector<std::string>& services,
                                const std::vector<std::string>& files);

}  // namespace blook::kdu::core
