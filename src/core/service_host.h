// blook-kdu: vulnerable driver service installation.
//
// Stages an embedded driver image to a temporary .sys file, creates and starts
// a kernel service for it, opens its device, and remembers everything it
// touched so the session can clean up afterwards.
#pragma once

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "blook/kdu/types.h"
#include "core/win32.h"
#include "exploits/common/iexploit.h"

namespace blook::kdu::core {

struct StagedArtifact {
    std::string service_name;  // service key created for the driver
    std::string device_name;   // symbolic link the exploit opened
    std::string driver_path;   // staged .sys file on disk
    std::string driver_name;   // original driver file name (diagnostics)
    bool service_removed = false;
    bool file_removed = false;
};

class ServiceHost final : public exploits::IServiceHost {
   public:
    ServiceHost();
    ~ServiceHost() override;

    ServiceHost(const ServiceHost&) = delete;
    ServiceHost& operator=(const ServiceHost&) = delete;

    // Install + start + open. Returns the device I/O object.
    Result<std::unique_ptr<exploits::IDeviceIo>> start(
        const exploits::ExploitInfo& info) override;

    // Stop + delete the service (and its staged file).
    Result<void> stop(const exploits::ExploitInfo& info) override;

    // Stop/delete every staged driver and remove all on-disk artifacts.
    // Event log cleanup is opt-in because it destroys unrelated records.
    Result<CleanupReport> cleanup(bool clean_event_log = false);

    // Names of every service this host has ever created (cleanup evidence).
    [[nodiscard]] std::vector<std::string> service_history() const;
    [[nodiscard]] std::vector<StagedArtifact> staged() const;

   private:
    Result<ServiceControl*> scm();

    mutable std::mutex mutex_;
    std::optional<ServiceControl> scm_;
    std::vector<StagedArtifact> staged_;
    std::vector<std::string> history_;
};

}  // namespace blook::kdu::core
