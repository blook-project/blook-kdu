// blook-kdu CLI: `payload` commands.
//
// `payload load` brings up the embedded blook-drv-lite image without needing a
// vulnerable driver (service path), then exercises the kernel-access client:
// kernel module list, a kernel virtual read, a CR3 process read and the DSE
// query. With --unsigned-driver it also proves DSE gating by starting a driver
// that would otherwise be rejected. This is the command used by the VM e2e and
// by CI's real kernel-load job.
#include <nlohmann/json.hpp>

#include <windows.h>

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "cli/commands.h"
#include "cli/output.h"
#include "core/win32.h"
#include "ipc/payload_client.h"

namespace blook::kdu::cli {
namespace {

blook::kdu::PayloadLoadMode parse_mode(const std::string& text) {
    if (text == "manual" || text == "manual_map") {
        return blook::kdu::PayloadLoadMode::manual_map;
    }
    if (text == "service") {
        return blook::kdu::PayloadLoadMode::service;
    }
    if (text == "auto" || text == "automatic") {
        return blook::kdu::PayloadLoadMode::automatic;
    }
    throw CliError(
        blook::kdu::Status::invalid_argument,
        "unknown payload mode: " + text + " (expected auto|manual|service)");
}

std::string bytes_to_hex(const std::uint8_t* bytes, std::size_t size) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string text;
    text.reserve(size * 2);
    for (std::size_t index = 0; index < size; ++index) {
        text.push_back(kDigits[bytes[index] >> 4]);
        text.push_back(kDigits[bytes[index] & 0x0F]);
    }
    return text;
}

struct PayloadState {
    std::string mode = "service";
    std::string unsigned_driver;
};

struct SelfTest {
    std::uint64_t payload_base = 0;
    std::uint64_t payload_size = 0;
    std::uint64_t ntoskrnl_base = 0;
    std::string ntoskrnl_head;
    std::string process_read;
    bool process_ok = false;
    bool process_write_ok = false;
    std::string physical_read;
    bool handle_ok = false;
    std::string dse_error;
    bool service_running = false;
    std::string service_state;
    bool dse_supported = false;
    bool dse_enabled = false;
    std::uint32_t dse_options = 0;
    bool unsigned_attempted = false;
    bool unsigned_loaded = false;
    std::string unsigned_error;
    std::vector<std::string> modules;
};

void run_self_test(const PayloadState& state, SelfTest* out) {
    auto backend = blook::kdu::ipc::create_payload_backend();
    if (!backend) {
        throw CliError(
            blook::kdu::Status::payload_unavailable,
            "this build has no payload backend (needs blook-kchannel "
            "and blook-drv-lite)");
    }
    blook::kdu::MapOptions options;
    options.name = "kdu-payload-selftest";
    options.payload_load_mode = parse_mode(state.mode);
    blook::kdu::MappedImage mapping{};
    auto attached = backend->map(nullptr, options, &mapping);
    if (!attached) {
        throw CliError(attached.error().code, attached.error().message);
    }
    auto& access = *attached.value();
    // Always unload (shutdown + service removal) even when a later assertion
    // throws: a left-over service keeps a stale bootstrap and breaks the next
    // load.
    struct UnloadGuard {
        blook::kdu::ipc::IPayloadBackend* backend = nullptr;
        ~UnloadGuard() { (void)backend->unload(); }
    } guard{backend.get()};
    out->payload_base = mapping.base;
    out->payload_size = mapping.size;

    auto modules = access.enumerate_modules();
    if (!modules) {
        throw CliError(modules.error().code, modules.error().message);
    }
    const blook::kdu::ModuleInfo* ntos = nullptr;
    for (const auto& module : modules.value()) {
        out->modules.push_back(module.name);
        if (_stricmp(module.name.c_str(), "ntoskrnl.exe") == 0) {
            ntos = &module;
        }
    }
    if (ntos == nullptr) {
        std::string names;
        for (std::size_t index = 0;
             index < modules.value().size() && index < 12; ++index) {
            names += modules.value()[index].name + " ";
        }
        throw CliError(blook::kdu::Status::not_found,
                       "ntoskrnl.exe is not in the kernel module list (" +
                           std::to_string(modules.value().size()) +
                           " modules: " + names + ")");
    }
    out->ntoskrnl_base = ntos->base;
    std::uint8_t head[2] = {};
    auto header = access.read_virtual(ntos->base, head, sizeof(head));
    if (!header) {
        throw CliError(header.error().code,
                       "kernel virtual read failed: " + header.error().message);
    }
    out->ntoskrnl_head = bytes_to_hex(head, sizeof(head));

    std::uint8_t physical[16] = {};
    auto physical_bytes =
        access.read_physical(0x1000, physical, sizeof(physical));
    if (physical_bytes) {
        out->physical_read = bytes_to_hex(physical, sizeof(physical));
    }

    auto handle =
        backend->open_process_handle(::GetCurrentProcessId(), 0x1FFFFF);
    if (handle) {
        out->handle_ok =
            backend->close_handle(handle.value(), ::GetCurrentProcessId())
                .has_value();
    }

    std::uint8_t pattern[16] = {0x4B, 0x44, 0x55, 0x2D, 0x50, 0x41, 0x59, 0x4C,
                                0x4F, 0x41, 0x44, 0x2D, 0x54, 0x45, 0x53, 0x54};
    auto self_read = access.read_process(
        ::GetCurrentProcessId(), reinterpret_cast<std::uint64_t>(pattern),
        pattern, sizeof(pattern));
    if (self_read) {
        out->process_read = bytes_to_hex(pattern, sizeof(pattern));
        out->process_ok = out->process_read.rfind("4b44552d5041594c", 0) == 0;
        std::uint8_t written[16] = {0x4B, 0x44, 0x55, 0x2D, 0x57, 0x52,
                                    0x49, 0x54, 0x45, 0x2D, 0x4F, 0x4B,
                                    0x21, 0x00, 0x00, 0x00};
        auto self_write = access.write_process(
            ::GetCurrentProcessId(), reinterpret_cast<std::uint64_t>(pattern),
            written, sizeof(written));
        if (self_write) {
            std::uint8_t read_back[16] = {};
            auto self_read_back =
                access.read_process(::GetCurrentProcessId(),
                                    reinterpret_cast<std::uint64_t>(pattern),
                                    read_back, sizeof(read_back));
            out->process_write_ok =
                self_read_back &&
                std::memcmp(read_back, written, sizeof(written)) == 0;
            std::memcpy(pattern, read_back, sizeof(pattern));
            std::uint8_t original[16] = {0x4B, 0x44, 0x55, 0x2D, 0x50, 0x41,
                                         0x59, 0x4C, 0x4F, 0x41, 0x44, 0x2D,
                                         0x54, 0x45, 0x53, 0x54};
            (void)access.write_process(::GetCurrentProcessId(),
                                       reinterpret_cast<std::uint64_t>(pattern),
                                       original, sizeof(original));
        }
    }

    if (state.mode != "manual" && state.mode != "manual_map") {
        auto manager = blook::kdu::core::ServiceControl::open();
        if (manager) {
            auto status = manager->query(L"kduPayload");
            if (status) {
                out->service_running = status.value().state == SERVICE_RUNNING;
                out->service_state = std::to_string(status.value().state);
            }
        }
    }

    auto dse = backend->dse_state();
    if (dse) {
        out->dse_supported = true;
        out->dse_enabled = dse->enabled;
        out->dse_options = dse->options;
    } else {
        out->dse_error = dse.error().message;
    }

    if (!state.unsigned_driver.empty()) {
        out->unsigned_attempted = true;
        auto disabled = backend->dse_disable();
        if (!disabled) {
            out->unsigned_error =
                "dse disable failed: " + disabled.error().message;
        } else {
            auto manager = blook::kdu::core::ServiceControl::open();
            if (!manager) {
                out->unsigned_error = manager.error().message;
            } else {
                const std::wstring name = L"kduUnsignedSelfTest";
                auto created = manager->create_driver(
                    name, blook::kdu::core::to_utf16(state.unsigned_driver));
                if (!created) {
                    out->unsigned_error = created.error().message;
                } else {
                    auto started = manager->start(name);
                    out->unsigned_loaded = static_cast<bool>(started);
                    if (!out->unsigned_loaded) {
                        out->unsigned_error = started.error().message;
                    }
                    (void)manager->stop(name);
                    (void)manager->remove(name);
                }
            }
            auto restored = backend->dse_restore();
            if (!restored) {
                out->unsigned_error +=
                    " (dse restore failed: " + restored.error().message + ")";
            }
        }
    }
}

}  // namespace

void add_payload_command(CLI::App& app, Context& context) {
    auto* payload = app.add_subcommand(
        "payload", "Load and exercise the embedded drv-lite payload backend");
    payload->require_subcommand(1);

    auto state = std::make_shared<PayloadState>();
    auto* load = payload->add_subcommand(
        "load", "Attach the payload and run a kernel-access self-test");
    load->add_option("--mode", state->mode,
                     "Load strategy: auto|manual|service (default service)");
    load->add_option("--unsigned-driver", state->unsigned_driver,
                     "Optional unsigned driver to prove DSE gating");
    load->callback([&context, state] {
        SelfTest result;
        run_self_test(*state, &result);
        if (context.options.json) {
            nlohmann::json modules = nlohmann::json::array();
            for (const auto& name : result.modules) {
                modules.push_back(name);
            }
            nlohmann::json document = {
                {"loaded", true},
                {"payload_base", hex(result.payload_base)},
                {"payload_size", result.payload_size},
                {"ntoskrnl_base", hex(result.ntoskrnl_base)},
                {"ntoskrnl_head", result.ntoskrnl_head},
                {"process_read", result.process_read},
                {"process_ok", result.process_ok},
                {"process_write_ok", result.process_write_ok},
                {"physical_read", result.physical_read},
                {"handle_ok", result.handle_ok},
                {"dse_error", result.dse_error},
                {"service_running", result.service_running},
                {"dse_supported", result.dse_supported},
                {"dse_enabled", result.dse_enabled},
                {"dse_options", hex(result.dse_options)},
                {"modules", std::move(modules)},
            };
            if (result.unsigned_attempted) {
                document["unsigned_driver"] = {
                    {"loaded", result.unsigned_loaded},
                    {"error", result.unsigned_error},
                };
            }
            std::printf("%s\n", document.dump(2).c_str());
        } else {
            std::vector<std::vector<std::string>> rows = {
                {"Item", "Value"},
                {"Payload base", hex(result.payload_base)},
                {"Payload size", std::to_string(result.payload_size)},
                {"ntoskrnl base", hex(result.ntoskrnl_base)},
                {"ntoskrnl head", result.ntoskrnl_head},
                {"process read", result.process_read},
                {"process ok", result.process_ok ? green("yes") : red("no")},
                {"DSE supported", result.dse_supported ? "yes" : "no"},
                {"DSE options", hex(result.dse_options)},
            };
            if (result.unsigned_attempted) {
                rows.push_back({"unsigned driver", result.unsigned_loaded
                                                       ? green("loaded")
                                                       : red("blocked")});
            }
            std::printf("%s", render_table(rows).c_str());
        }
        if (!result.process_ok || !result.process_write_ok ||
            !result.service_running || !result.handle_ok ||
            result.physical_read.empty() || result.ntoskrnl_head != "4d5a") {
            throw CliError(blook::kdu::Status::io_error,
                           "payload self-test assertions failed");
        }
        if (result.unsigned_attempted && !result.unsigned_loaded) {
            throw CliError(
                blook::kdu::Status::access_denied,
                "unsigned driver was not accepted after DSE disable");
        }
    });
}

}  // namespace blook::kdu::cli
