// blook-kdu: public SDK implementation.
#include "blook/kdu/kdu.h"

#include <algorithm>
#include <mutex>

#include "core/log.h"
#include "core/module_enum.h"
#include "core/service_host.h"
#include "core/trace.h"
#include <cstdlib>

#include "core/win32.h"
#include "exploits/common/driver_kernel_access.h"
#include "ipc/payload_client.h"
#include "loader/manual_map.h"
#include "sdk/dse.h"

namespace blook::kdu {
namespace {

constexpr std::size_t kDumpChunk = 0x10000;

std::string resolve_kernel_file_path(const std::string& path) {
    const std::string system_root = core::system_root();
    std::string resolved = path;
    const std::string prefix = "\\SystemRoot";
    if (resolved.rfind(prefix, 0) == 0) {
        resolved = system_root + resolved.substr(prefix.size());
    } else if (resolved.rfind("\\??\\", 0) == 0) {
        resolved = resolved.substr(4);
    } else if (resolved.rfind("\\Device\\HarddiskVolume", 0) == 0) {
        // Best effort: map to the system drive via the system root.
        const auto colon = system_root.find(':');
        if (colon != std::string::npos) {
            const auto slash = resolved.find('\\', 18);
            if (slash != std::string::npos) {
                resolved =
                    system_root.substr(0, colon + 1) + resolved.substr(slash);
            }
        }
    }
    return resolved;
}

}  // namespace

// ---------------------------------------------------------------------------
// Session::Impl
// ---------------------------------------------------------------------------
struct Session::Impl {
    OpenOptions options;
    SessionInfo info;
    std::unique_ptr<exploits::IExploit> exploit;
    std::unique_ptr<exploits::IDriverInterface> driver;
    std::unique_ptr<core::ServiceHost> services;
    std::unique_ptr<IKernelAccess> access;
    std::unique_ptr<ipc::IPayloadBackend> payload;
    std::unique_ptr<ManualMapper> mapper;
    std::vector<MappedImage> mappings;
    std::optional<sdk::CiOptionsLocation> ci_options_location;
    std::optional<std::uint32_t> original_ci_options;
    bool payload_mapped = false;
    bool closed = false;
    mutable std::mutex mutex;

    ~Impl() {
        if (options.cleanup_on_close) {
            (void)close(true);
        } else {
            (void)close(false);
        }
    }

    Result<CleanupReport> close(bool do_cleanup) {
        std::lock_guard<std::mutex> lock(mutex);
        CleanupReport report;
        if (closed) {
            return Result<CleanupReport>::ok(report);
        }
        closed = true;

        // Restore any DSE change before tearing the backends down.
        if (original_ci_options && ci_options_location && access) {
            (void)sdk::write_ci_options(*access, ci_options_location->address,
                                        *original_ci_options);
            original_ci_options.reset();
        }
        if (payload_mapped && payload) {
            (void)payload->unload();
            payload_mapped = false;
        }
        payload.reset();
        mappings.clear();
        mapper.reset();
        if (driver) {
            driver->close();
        }
        if (services && do_cleanup) {
            auto cleanup = services->cleanup(false);
            if (cleanup) {
                report = cleanup.value();
            } else {
                report.clean = false;
                report.residuals.push_back(cleanup.error().message);
            }
        }
        if (exploit && services) {
            exploit->cleanup(*services);
        }
        driver.reset();
        access.reset();
        return Result<CleanupReport>::ok(report);
    }

    [[nodiscard]] bool valid() const noexcept {
        return !closed && access != nullptr;
    }

    Result<std::vector<core::KernelModuleEntry>> kernel_modules() {
        auto modules = core::enum_kernel_modules();
        if (!modules) {
            return Result<std::vector<core::KernelModuleEntry>>::fail(
                modules.error().code, modules.error().message);
        }
        return modules;
    }

    void refresh_info_capabilities() {
        info.capabilities.clear();
        if (access) {
            info.capabilities =
                exploits::capability_names(access->capabilities());
            info.backend = std::string(access->backend_name());
        }
    }
};

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------
Session::Session() noexcept = default;

Session::~Session() = default;

Session::Session(Session&& other) noexcept = default;

Session& Session::operator=(Session&& other) noexcept = default;

const SessionInfo& Session::info() const noexcept {
    static const SessionInfo kEmpty{};
    return impl_ ? impl_->info : kEmpty;
}

bool Session::valid() const noexcept {
    return impl_ && impl_->valid();
}

Result<CleanupReport> Session::close() {
    if (!impl_) {
        return Result<CleanupReport>::fail(Status::invalid_argument,
                                           "session is not open");
    }
    return impl_->close(true);
}

// ---------------------------------------------------------------------------
// Payload / mapping
// ---------------------------------------------------------------------------
Result<MappedImage> Session::map_payload(const MapOptions& options) {
    if (!valid()) {
        return Result<MappedImage>::fail(Status::invalid_argument,
                                         "session is not open");
    }
    if (impl_->payload_mapped) {
        MappedImage mapping{};
        mapping.name = "blook-kdu-payload";
        mapping.base = impl_->info.payload_base;
        mapping.size = impl_->info.payload_size;
        return Result<MappedImage>::ok(mapping);
    }
    if (!impl_->payload) {
        impl_->payload = ipc::create_payload_backend();
    }
    if (!impl_->payload) {
        return Result<MappedImage>::fail(
            Status::payload_unavailable,
            "this build has no blook-kchannel support; rebuild with "
            "--kchannel_dir=<path>");
    }
    if (!impl_->mapper) {
        impl_->mapper =
            std::make_unique<ManualMapper>(*impl_->access, *impl_->services);
    }
    MappedImage mapping{};
    auto result = impl_->payload->map(*impl_->mapper, options, &mapping);
    if (!result) {
        return Result<MappedImage>::fail(result.error().code,
                                         result.error().message);
    }
    impl_->access = std::move(result.value());
    impl_->payload_mapped = true;
    impl_->info.payload_mapped = true;
    impl_->info.payload_base = mapping.base;
    impl_->info.payload_size = mapping.size;
    impl_->refresh_info_capabilities();
    return Result<MappedImage>::ok(mapping);
}

Result<MappedImage> Session::map_driver(std::span<const std::uint8_t> image,
                                        const MapOptions& options) {
    if (!valid()) {
        return Result<MappedImage>::fail(Status::invalid_argument,
                                         "session is not open");
    }
    if (!impl_->mapper) {
        impl_->mapper =
            std::make_unique<ManualMapper>(*impl_->access, *impl_->services);
    }
    auto result = impl_->exploit ? impl_->exploit->map_driver(image, options,
                                                              *impl_->mapper)
                                 : impl_->mapper->map(image, options);
    if (!result) {
        return result;
    }
    impl_->mappings.push_back(result.value());
    return result;
}

Result<void> Session::unmap(std::uint64_t base) {
    if (!impl_ || !impl_->mapper) {
        return Result<void>::fail(Status::invalid_argument,
                                  "nothing has been mapped");
    }
    auto result = impl_->mapper->unmap(base);
    if (result) {
        auto& mappings = impl_->mappings;
        mappings.erase(std::remove_if(mappings.begin(), mappings.end(),
                                      [base](const MappedImage& image) {
                                          return image.base == base;
                                      }),
                       mappings.end());
    }
    return result;
}

Result<void> Session::unload_payload() {
    if (!impl_ || !impl_->payload_mapped) {
        return Result<void>::ok();
    }
    auto result = impl_->payload->unload();
    if (!result) {
        return result;
    }
    impl_->payload_mapped = false;
    impl_->info.payload_mapped = false;
    if (impl_->driver) {
        impl_->access =
            std::make_unique<exploits::DriverKernelAccess>(*impl_->driver);
        impl_->refresh_info_capabilities();
    }
    return Result<void>::ok();
}

bool Session::payload_mapped() const noexcept {
    return impl_ && impl_->payload_mapped;
}

// ---------------------------------------------------------------------------
// Memory operations
// ---------------------------------------------------------------------------
Result<std::size_t> Session::read_physical(std::uint64_t address, void* buffer,
                                           std::size_t size) {
    if (!valid()) {
        return Result<std::size_t>::fail(Status::invalid_argument,
                                         "session is not open");
    }
    return impl_->access->read_physical(address, buffer, size);
}

Result<std::size_t> Session::write_physical(std::uint64_t address,
                                            const void* buffer,
                                            std::size_t size) {
    if (!valid()) {
        return Result<std::size_t>::fail(Status::invalid_argument,
                                         "session is not open");
    }
    return impl_->access->write_physical(address, buffer, size);
}

Result<std::size_t> Session::read_virtual(std::uint64_t address, void* buffer,
                                          std::size_t size) {
    if (!valid()) {
        return Result<std::size_t>::fail(Status::invalid_argument,
                                         "session is not open");
    }
    return impl_->access->read_virtual(address, buffer, size);
}

Result<std::size_t> Session::write_virtual(std::uint64_t address,
                                           const void* buffer,
                                           std::size_t size) {
    if (!valid()) {
        return Result<std::size_t>::fail(Status::invalid_argument,
                                         "session is not open");
    }
    return impl_->access->write_virtual(address, buffer, size);
}

Result<std::uint64_t> Session::translate_virtual(std::uint64_t address) {
    if (!valid()) {
        return Result<std::uint64_t>::fail(Status::invalid_argument,
                                           "session is not open");
    }
    return impl_->access->translate(address);
}

Result<std::vector<std::uint8_t>> Session::read_physical_bytes(
    std::uint64_t address, std::size_t size) {
    std::vector<std::uint8_t> bytes(size);
    auto result = read_physical(address, bytes.data(), bytes.size());
    if (!result) {
        return Result<std::vector<std::uint8_t>>::fail(result.error().code,
                                                       result.error().message);
    }
    bytes.resize(result.value());
    return Result<std::vector<std::uint8_t>>::ok(std::move(bytes));
}

Result<void> Session::write_physical_bytes(
    std::uint64_t address, std::span<const std::uint8_t> bytes) {
    auto result = write_physical(address, bytes.data(), bytes.size());
    if (!result) {
        return Result<void>::fail(result.error().code, result.error().message);
    }
    return Result<void>::ok();
}

Result<std::vector<std::uint8_t>> Session::read_virtual_bytes(
    std::uint64_t address, std::size_t size) {
    if (!valid()) {
        return Result<std::vector<std::uint8_t>>::fail(Status::invalid_argument,
                                                       "session is not open");
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(size);
    std::size_t offset = 0;
    while (offset < size) {
        const auto chunk = std::min(kDumpChunk, size - offset);
        std::vector<std::uint8_t> piece(chunk);
        auto result =
            impl_->access->read_virtual(address + offset, piece.data(), chunk);
        if (!result) {
            return Result<std::vector<std::uint8_t>>::fail(
                result.error().code, result.error().message);
        }
        bytes.insert(
            bytes.end(), piece.begin(),
            piece.begin() + static_cast<std::ptrdiff_t>(result.value()));
        offset += result.value();
        if (result.value() != chunk) {
            break;
        }
    }
    return Result<std::vector<std::uint8_t>>::ok(std::move(bytes));
}

Result<void> Session::write_virtual_bytes(std::uint64_t address,
                                          std::span<const std::uint8_t> bytes) {
    auto result = write_virtual(address, bytes.data(), bytes.size());
    if (!result) {
        return Result<void>::fail(result.error().code, result.error().message);
    }
    return Result<void>::ok();
}

// ---------------------------------------------------------------------------
// Process memory
// ---------------------------------------------------------------------------
Result<std::uint64_t> Session::process_cr3(std::uint32_t pid) {
    if (!valid()) {
        return Result<std::uint64_t>::fail(Status::invalid_argument,
                                           "session is not open");
    }
    return impl_->access->process_cr3(pid);
}

Result<std::size_t> Session::read_process(std::uint32_t pid,
                                          std::uint64_t address, void* buffer,
                                          std::size_t size) {
    if (!valid()) {
        return Result<std::size_t>::fail(Status::invalid_argument,
                                         "session is not open");
    }
    return impl_->access->read_process(pid, address, buffer, size);
}

Result<std::size_t> Session::write_process(std::uint32_t pid,
                                           std::uint64_t address,
                                           const void* buffer,
                                           std::size_t size) {
    if (!valid()) {
        return Result<std::size_t>::fail(Status::invalid_argument,
                                         "session is not open");
    }
    return impl_->access->write_process(pid, address, buffer, size);
}

Result<std::vector<std::uint8_t>> Session::read_process_bytes(
    std::uint32_t pid, std::uint64_t address, std::size_t size) {
    std::vector<std::uint8_t> bytes(size);
    auto result = read_process(pid, address, bytes.data(), bytes.size());
    if (!result) {
        return Result<std::vector<std::uint8_t>>::fail(result.error().code,
                                                       result.error().message);
    }
    bytes.resize(result.value());
    return Result<std::vector<std::uint8_t>>::ok(std::move(bytes));
}

Result<void> Session::write_process_bytes(std::uint32_t pid,
                                          std::uint64_t address,
                                          std::span<const std::uint8_t> bytes) {
    auto result = write_process(pid, address, bytes.data(), bytes.size());
    if (!result) {
        return Result<void>::fail(result.error().code, result.error().message);
    }
    return Result<void>::ok();
}

// ---------------------------------------------------------------------------
// DSE
// ---------------------------------------------------------------------------
Result<DseState> Session::dse_status() {
    if (!valid()) {
        return Result<DseState>::fail(Status::invalid_argument,
                                      "session is not open");
    }
    if (!impl_->ci_options_location) {
        auto modules = impl_->kernel_modules();
        if (!modules) {
            return Result<DseState>::fail(modules.error().code,
                                          modules.error().message);
        }
        auto location = sdk::find_ci_options(*impl_->access, modules.value());
        if (!location) {
            return Result<DseState>::fail(location.error().code,
                                          location.error().message);
        }
        impl_->ci_options_location = location.value();
        KDU_LOG_INFO("g_CiOptions at 0x{:x} (method: {})", location->address,
                     location->method);
    }
    auto value = sdk::read_ci_options(*impl_->access,
                                      impl_->ci_options_location->address);
    if (!value) {
        return Result<DseState>::fail(value.error().code,
                                      value.error().message);
    }
    DseState state;
    state.options = value.value();
    state.enabled = value.value() != 0;
    state.options_address = impl_->ci_options_location->address;
    return Result<DseState>::ok(state);
}

Result<void> Session::dse_disable() {
    auto status = dse_status();
    if (!status) {
        return Result<void>::fail(status.error().code, status.error().message);
    }
    if (!impl_->original_ci_options) {
        impl_->original_ci_options = status->options;
    }
    return sdk::write_ci_options(*impl_->access, status->options_address, 0);
}

Result<void> Session::dse_restore() {
    auto status = dse_status();
    if (!status) {
        return Result<void>::fail(status.error().code, status.error().message);
    }
    const std::uint32_t value =
        impl_->original_ci_options.value_or(6);  // 6 = default DSE on
    auto result =
        sdk::write_ci_options(*impl_->access, status->options_address, value);
    if (result) {
        impl_->original_ci_options.reset();
    }
    return result;
}

// ---------------------------------------------------------------------------
// Introspection
// ---------------------------------------------------------------------------
Result<std::vector<ModuleInfo>> Session::enum_modules() {
    auto modules = impl_ ? impl_->kernel_modules()
                         : Result<std::vector<core::KernelModuleEntry>>::fail(
                               Status::invalid_argument, "session is not open");
    if (!modules) {
        return Result<std::vector<ModuleInfo>>::fail(modules.error().code,
                                                     modules.error().message);
    }
    std::vector<ModuleInfo> result;
    result.reserve(modules->size());
    for (const auto& module : modules.value()) {
        ModuleInfo info;
        info.name = module.name;
        info.path = module.path;
        info.base = module.base;
        info.size = module.size;
        result.push_back(std::move(info));
    }
    return Result<std::vector<ModuleInfo>>::ok(std::move(result));
}

Result<ModuleInfo> Session::find_module(std::string_view name) {
    auto modules = enum_modules();
    if (!modules) {
        return Result<ModuleInfo>::fail(modules.error().code,
                                        modules.error().message);
    }
    auto lowered = std::string(name);
    std::transform(
        lowered.begin(), lowered.end(), lowered.begin(),
        [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    for (const auto& module : modules.value()) {
        auto module_name = module.name;
        std::transform(
            module_name.begin(), module_name.end(), module_name.begin(),
            [](unsigned char c) { return static_cast<char>(::tolower(c)); });
        if (module_name == lowered) {
            return Result<ModuleInfo>::ok(module);
        }
    }
    return Result<ModuleInfo>::fail(Status::not_found, "module not loaded");
}

Result<std::vector<std::uint8_t>> Session::dump_driver(
    const DumpOptions& options) {
    if (!valid()) {
        return Result<std::vector<std::uint8_t>>::fail(Status::invalid_argument,
                                                       "session is not open");
    }
    if (options.from_disk) {
        return core::read_file(resolve_kernel_file_path(options.module));
    }
    auto module = find_module(options.module);
    if (!module) {
        return Result<std::vector<std::uint8_t>>::fail(module.error().code,
                                                       module.error().message);
    }
    std::vector<std::uint8_t> image(module->size, 0);
    std::size_t valid = 0;
    for (std::size_t offset = 0; offset < image.size(); offset += 0x1000) {
        const auto chunk = std::min<std::size_t>(0x1000, image.size() - offset);
        auto result = impl_->access->read_virtual(module->base + offset,
                                                  image.data() + offset, chunk);
        if (result && result.value() == chunk) {
            valid += result.value();
        }
    }
    KDU_LOG_INFO("dumped {} ({} bytes, {} readable)", module->name,
                 module->size, valid);
    return Result<std::vector<std::uint8_t>>::ok(std::move(image));
}

// ---------------------------------------------------------------------------
// Cleanup / trace scanning
// ---------------------------------------------------------------------------
Result<CleanupReport> Session::cleanup(const CleanupOptions& options) {
    if (!impl_) {
        return Result<CleanupReport>::fail(Status::invalid_argument,
                                           "session is not open");
    }
    CleanupReport report;
    if (options.unload_driver || options.remove_service_file ||
        options.remove_registry) {
        auto closed = impl_->close(true);
        if (closed) {
            report = closed.value();
        } else {
            report.clean = false;
            report.residuals.push_back(closed.error().message);
        }
    }
    if (options.clean_event_log) {
        auto result = core::clear_system_event_log();
        if (result) {
            report.actions.push_back("cleared System event log");
        } else {
            report.residuals.push_back("event log not cleared: " +
                                       result.error().message);
            report.clean = false;
        }
    }
    if (options.scan_traces) {
        auto traces = scan_traces();
        if (!traces) {
            report.residuals.push_back(traces.error().message);
            report.clean = false;
        } else if (!traces->clean()) {
            for (const auto& finding : traces->findings) {
                report.residuals.push_back(finding.category + ": " +
                                           finding.description + " (" +
                                           finding.location + ")");
            }
            report.clean = false;
        }
    }
    return Result<CleanupReport>::ok(report);
}

Result<TraceReport> Session::scan_traces() {
    if (!impl_) {
        return Result<TraceReport>::fail(Status::invalid_argument,
                                         "session is not open");
    }
    TraceReport report;
    auto history = impl_->services ? impl_->services->service_history()
                                   : std::vector<std::string>{};
    std::vector<std::string> files;
    if (impl_->services) {
        for (const auto& artifact : impl_->services->staged()) {
            files.push_back(artifact.driver_path);
        }
    }
    auto scan = core::scan_traces(history, files);
    if (!scan) {
        return Result<TraceReport>::fail(scan.error().code,
                                         scan.error().message);
    }
    report = scan.value();
    if (impl_->options.cleanup_on_close) {
        // Informational: the session will tear the driver down on close.
        for (auto& finding : report.findings) {
            if (!finding.cleaned) {
                break;
            }
        }
    }
    return Result<TraceReport>::ok(report);
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------
Result<Session> kdu_open(const OpenOptions& options) {
    core::init_logging(options.log_level, options.log_file);

    // Safety gate: this tool loads kernel drivers, maps payloads and can patch
    // DSE. Running that on a physical host is unsupported and dangerous (host
    // hangs/reboots have been observed), so refuse unless we are clearly inside
    // a VMware guest, which is exactly what bvmenv manages.
    {
        std::string vendor;
        const bool vmware = core::is_running_under_hypervisor(&vendor) &&
                            vendor.find("VMware") != std::string::npos;
        if (!vmware) {
            return Result<Session>::fail(
                Status::access_denied,
                "refusing to load kernel exploitation code outside a bvmenv "
                "VMware guest (hypervisor vendor: " +
                    (vendor.empty() ? std::string("none") : vendor) +
                    "). Kernel experiments are VM-only; see docs/e2e.md.");
        }
    }
    KDU_LOG_DEBUG("kdu_open: build {} ({}), exploit='{}'",
                  BLOOK_KDU_VERSION_STRING, core::windows_version_string(),
                  options.exploit);

    auto session = Session();
    auto impl = std::make_unique<Session::Impl>();
    impl->options = options;
    impl->services = std::make_unique<core::ServiceHost>();

    std::vector<const exploits::ExploitDescriptor*> candidates;
    if (!options.exploit.empty()) {
        const auto* descriptor = exploits::find_exploit(options.exploit);
        if (!descriptor) {
            return Result<Session>::fail(Status::no_suitable_exploit,
                                         "unknown exploit '" + options.exploit +
                                             "' (see kdu exploits list)");
        }
        candidates.push_back(descriptor);
    } else {
        for (const auto& descriptor : exploits::all_exploits()) {
            candidates.push_back(&descriptor);
        }
    }
    if (candidates.empty()) {
        return Result<Session>::fail(Status::no_suitable_exploit,
                                     "no exploits are compiled in");
    }

    std::string last_error = "no exploit could open a kernel driver";
    for (const auto* candidate : candidates) {
        auto exploit = candidate->create();
        auto probe = exploit->probe();
        if (!probe) {
            last_error =
                std::string(candidate->id) + ": " + probe.error().message;
            KDU_LOG_DEBUG("exploit {} probe failed: {}", candidate->id,
                          probe.error().message);
            continue;
        }
        KDU_LOG_INFO("trying exploit {} ({})", candidate->id,
                     exploit->info().description);
        auto opened = exploit->open(*impl->services);
        if (!opened) {
            last_error =
                std::string(candidate->id) + ": " + opened.error().message;
            KDU_LOG_DEBUG("exploit {} open failed: {}", candidate->id,
                          opened.error().message);
            continue;
        }
        impl->exploit = std::move(exploit);
        impl->driver = std::move(opened.value());
        impl->access =
            std::make_unique<exploits::DriverKernelAccess>(*impl->driver);
        impl->info.exploit = std::string(candidate->id);
        impl->info.driver_name = std::string(candidate->info().driver_file);
        impl->info.service_name = std::string(candidate->info().service_name);
        impl->info.windows_build = core::windows_build_number();
        impl->info.version = BLOOK_KDU_VERSION_STRING;
        impl->refresh_info_capabilities();
        KDU_LOG_INFO("exploit {} ready, backend '{}'", candidate->id,
                     impl->info.backend);
        break;
    }
    if (!impl->access) {
        return Result<Session>::fail(Status::no_suitable_exploit, last_error);
    }

    if (options.use_payload) {
        impl->payload = ipc::create_payload_backend();
        if (!impl->payload) {
            const std::string message =
                "payload unavailable: build without blook-kchannel";
            if (!options.allow_driver_only) {
                return Result<Session>::fail(Status::payload_unavailable,
                                             message);
            }
            KDU_LOG_WARN("{}; continuing with the driver backend", message);
        } else {
            impl->mapper =
                std::make_unique<ManualMapper>(*impl->access, *impl->services);
            MappedImage mapping{};
            auto mapped =
                impl->payload->map(*impl->mapper, MapOptions{}, &mapping);
            if (mapped) {
                impl->access = std::move(mapped.value());
                impl->payload_mapped = true;
                impl->info.payload_mapped = true;
                impl->info.payload_base = mapping.base;
                impl->info.payload_size = mapping.size;
                impl->refresh_info_capabilities();
                KDU_LOG_INFO("payload mapped at 0x{:x}", mapping.base);
            } else {
                if (!options.allow_driver_only) {
                    return Result<Session>::fail(
                        mapped.error().code,
                        "payload mapping failed: " + mapped.error().message);
                }
                KDU_LOG_WARN(
                    "payload mapping failed ({}); continuing with the driver "
                    "backend",
                    mapped.error().message);
            }
        }
    }

    session.impl_ = std::move(impl);
    return Result<Session>::ok(std::move(session));
}

Result<CleanupReport> kdu_close(Session& session) {
    return session.close();
}

Result<MappedImage> kdu_map_payload(Session& session,
                                    const MapOptions& options) {
    return session.map_payload(options);
}

Result<MappedImage> kdu_map_driver(Session& session,
                                   std::span<const std::uint8_t> image,
                                   const MapOptions& options) {
    return session.map_driver(image, options);
}

Result<void> kdu_unmap(Session& session, std::uint64_t base) {
    return session.unmap(base);
}

Result<void> kdu_unload_payload(Session& session) {
    return session.unload_payload();
}

Result<std::size_t> kdu_read_physical(Session& session, std::uint64_t address,
                                      void* buffer, std::size_t size) {
    return session.read_physical(address, buffer, size);
}

Result<std::size_t> kdu_write_physical(Session& session, std::uint64_t address,
                                       const void* buffer, std::size_t size) {
    return session.write_physical(address, buffer, size);
}

Result<std::size_t> kdu_read_virtual(Session& session, std::uint64_t address,
                                     void* buffer, std::size_t size) {
    return session.read_virtual(address, buffer, size);
}

Result<std::size_t> kdu_write_virtual(Session& session, std::uint64_t address,
                                      const void* buffer, std::size_t size) {
    return session.write_virtual(address, buffer, size);
}

Result<std::uint64_t> kdu_translate_virtual(Session& session,
                                            std::uint64_t address) {
    return session.translate_virtual(address);
}

Result<std::size_t> kdu_read_process(Session& session, std::uint32_t pid,
                                     std::uint64_t address, void* buffer,
                                     std::size_t size) {
    return session.read_process(pid, address, buffer, size);
}

Result<std::size_t> kdu_write_process(Session& session, std::uint32_t pid,
                                      std::uint64_t address, const void* buffer,
                                      std::size_t size) {
    return session.write_process(pid, address, buffer, size);
}

Result<std::uint64_t> kdu_process_cr3(Session& session, std::uint32_t pid) {
    return session.process_cr3(pid);
}

Result<DseState> kdu_dse_status(Session& session) {
    return session.dse_status();
}

Result<void> kdu_dse_disable(Session& session) {
    return session.dse_disable();
}

Result<void> kdu_dse_restore(Session& session) {
    return session.dse_restore();
}

Result<std::vector<ModuleInfo>> kdu_enum_modules(Session& session) {
    return session.enum_modules();
}

Result<std::vector<std::uint8_t>> kdu_dump_driver(Session& session,
                                                  const DumpOptions& options) {
    return session.dump_driver(options);
}

Result<CleanupReport> kdu_cleanup(Session& session,
                                  const CleanupOptions& options) {
    return session.cleanup(options);
}

Result<TraceReport> kdu_scan_traces(Session& session) {
    return session.scan_traces();
}

}  // namespace blook::kdu
