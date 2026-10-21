// blook-kdu CLI: `batch` command.
//
// Executes a JSON-described sequence of SDK operations in one session. This is
// the scripting/e2e workhorse: a single process opens the driver once, performs
// N operations and reports structured results (and the process exit code only
// reflects the batch verdict).
//
// Input:  { "ops": [ { "op": "read_virtual", "address": "0xfffff800...",
//                     "size": 64, "out": "C:\\dump.bin" }, ... ] }
// Output: { "ok": true, "results": [ { "op": "...", "status": "ok", ... } ] }
#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "cli/commands.h"
#include "cli/output.h"

namespace blook::kdu::cli {
namespace {

std::string bytes_to_hex(const std::vector<std::uint8_t>& bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string text;
    text.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        text.push_back(kDigits[byte >> 4]);
        text.push_back(kDigits[byte & 0x0F]);
    }
    return text;
}

std::uint64_t json_u64(const nlohmann::json& value) {
    if (value.is_number_unsigned() || value.is_number_integer()) {
        return value.get<std::uint64_t>();
    }
    if (value.is_string()) {
        return parse_u64(value.get<std::string>());
    }
    throw CliError(blook::kdu::Status::invalid_argument,
                   "expected a numeric or string address/size");
}

std::uint32_t json_u32(const nlohmann::json& value) {
    const auto wide = json_u64(value);
    if (wide > 0xFFFF'FFFFull) {
        throw CliError(blook::kdu::Status::invalid_argument,
                       "value does not fit in 32 bits");
    }
    return static_cast<std::uint32_t>(wide);
}

std::vector<std::uint8_t> json_bytes(const nlohmann::json& value) {
    if (!value.is_string()) {
        throw CliError(blook::kdu::Status::invalid_argument,
                       "expected a hex byte string");
    }
    return parse_hex_bytes(value.get<std::string>());
}

// Returns the result object for one operation; throws CliError on failure when
// the batch is not running in continue-on-error mode.
nlohmann::json execute(const nlohmann::json& operation,
                       blook::kdu::Session& session) {
    const auto name = operation.at("op").get<std::string>();
    nlohmann::json result;
    result["op"] = name;
    const auto& arguments = operation;

    auto read_memory = [&](bool physical) {
        const auto address = json_u64(arguments.at("address"));
        const auto size =
            static_cast<std::size_t>(json_u64(arguments.at("size")));
        auto bytes = physical ? session.read_physical_bytes(address, size)
                              : session.read_virtual_bytes(address, size);
        if (!bytes) {
            throw CliError(bytes.error().code, bytes.error().message);
        }
        result["address"] = hex(address);
        result["size"] = bytes->size();
        result["hex"] = bytes_to_hex(bytes.value());
        if (arguments.contains("out")) {
            save_file(arguments.at("out").get<std::string>(), bytes.value());
            result["written_to"] = arguments.at("out");
        }
    };

    auto write_memory = [&](bool physical) {
        const auto address = json_u64(arguments.at("address"));
        const auto bytes = json_bytes(arguments.at("hex"));
        auto written =
            physical
                ? session.write_physical(address, bytes.data(), bytes.size())
                : session.write_virtual(address, bytes.data(), bytes.size());
        if (!written) {
            throw CliError(written.error().code, written.error().message);
        }
        result["address"] = hex(address);
        result["size"] = written.value();
    };

    if (name == "read_physical" || name == "read_virtual") {
        read_memory(name == "read_physical");
        return result;
    }
    if (name == "write_physical" || name == "write_virtual") {
        write_memory(name == "write_physical");
        return result;
    }
    if (name == "read_process" || name == "write_process") {
        const auto pid = json_u32(arguments.at("pid"));
        const auto address = json_u64(arguments.at("address"));
        if (name == "read_process") {
            const auto size =
                static_cast<std::size_t>(json_u64(arguments.at("size")));
            auto bytes = session.read_process_bytes(pid, address, size);
            if (!bytes) {
                throw CliError(bytes.error().code, bytes.error().message);
            }
            result["pid"] = pid;
            result["address"] = hex(address);
            result["size"] = bytes->size();
            result["hex"] = bytes_to_hex(bytes.value());
            if (arguments.contains("out")) {
                save_file(arguments.at("out").get<std::string>(),
                          bytes.value());
                result["written_to"] = arguments.at("out");
            }
        } else {
            const auto bytes = json_bytes(arguments.at("hex"));
            auto written =
                session.write_process(pid, address, bytes.data(), bytes.size());
            if (!written) {
                throw CliError(written.error().code, written.error().message);
            }
            result["pid"] = pid;
            result["address"] = hex(address);
            result["size"] = written.value();
        }
        return result;
    }
    if (name == "translate") {
        const auto address = json_u64(arguments.at("address"));
        auto physical = session.translate_virtual(address);
        if (!physical) {
            throw CliError(physical.error().code, physical.error().message);
        }
        result["virtual"] = hex(address);
        result["physical"] = hex(physical.value());
        return result;
    }
    if (name == "process_cr3") {
        const auto pid = json_u32(arguments.at("pid"));
        auto cr3 = session.process_cr3(pid);
        if (!cr3) {
            throw CliError(cr3.error().code, cr3.error().message);
        }
        result["pid"] = pid;
        result["cr3"] = hex(cr3.value());
        return result;
    }
    if (name == "map_payload") {
        blook::kdu::MapOptions options;
        options.name = arguments.value("name", std::string("batch-payload"));
        auto mapped = session.map_payload(options);
        if (!mapped) {
            throw CliError(mapped.error().code, mapped.error().message);
        }
        result["base"] = hex(mapped->base);
        result["size"] = mapped->size;
        result["entry_status"] = mapped->entry_status;
        return result;
    }
    if (name == "unload_payload") {
        auto outcome = session.unload_payload();
        if (!outcome) {
            throw CliError(outcome.error().code, outcome.error().message);
        }
        result["ok"] = true;
        return result;
    }
    if (name == "map_driver") {
        const auto image = load_file(arguments.at("file").get<std::string>());
        blook::kdu::MapOptions options;
        options.name = arguments.value("name", std::string("batch-image"));
        if (arguments.contains("bootstrap_hex")) {
            options.bootstrap = json_bytes(arguments.at("bootstrap_hex"));
        }
        options.call_entry = arguments.value("call_entry", true);
        auto mapped = session.map_driver(image, options);
        if (!mapped) {
            throw CliError(mapped.error().code, mapped.error().message);
        }
        result["base"] = hex(mapped->base);
        result["size"] = mapped->size;
        result["entry_status"] = mapped->entry_status;
        return result;
    }
    if (name == "unmap") {
        auto outcome = session.unmap(json_u64(arguments.at("base")));
        if (!outcome) {
            throw CliError(outcome.error().code, outcome.error().message);
        }
        result["ok"] = true;
        return result;
    }
    if (name == "dse_status") {
        auto status = session.dse_status();
        if (!status) {
            throw CliError(status.error().code, status.error().message);
        }
        result["enabled"] = status->enabled;
        result["options"] = hex(status->options);
        result["address"] = hex(status->options_address);
        return result;
    }
    if (name == "dse_disable" || name == "dse_restore") {
        auto outcome = name == "dse_disable" ? session.dse_disable()
                                             : session.dse_restore();
        if (!outcome) {
            throw CliError(outcome.error().code, outcome.error().message);
        }
        result["ok"] = true;
        return result;
    }
    if (name == "modules") {
        auto modules = session.enum_modules();
        if (!modules) {
            throw CliError(modules.error().code, modules.error().message);
        }
        nlohmann::json array = nlohmann::json::array();
        for (const auto& module : modules.value()) {
            array.push_back({{"name", module.name},
                             {"base", hex(module.base)},
                             {"size", module.size}});
        }
        result["count"] = modules->size();
        result["modules"] = std::move(array);
        return result;
    }
    if (name == "sleep") {
        const auto milliseconds = json_u32(arguments.at("ms"));
        ::Sleep(milliseconds);
        result["slept_ms"] = milliseconds;
        return result;
    }
    if (name == "ping") {
        result["ok"] = true;
        return result;
    }
    throw CliError(blook::kdu::Status::invalid_argument,
                   "unknown batch op: " + name);
}

}  // namespace

void add_batch_command(CLI::App& app, Context& context) {
    auto* batch = app.add_subcommand(
        "batch", "Execute a JSON-described batch of SDK operations");
    // Option storage is captured by value into the callback; keep the strings
    // alive by storing them in a shared state object.
    struct State {
        std::string file;
    };
    auto state = std::make_shared<State>();
    bool continue_on_error = false;
    batch->add_option("file", state->file, "Batch JSON file")->required();
    batch->add_flag("--continue-on-error", continue_on_error,
                    "Keep executing after a failed operation");
    batch->footer(
        "Example:\n"
        "  kdu batch ops.json\n"
        "  cat ops.json\n"
        "  { \"ops\": [ {\"op\":\"read_virtual\",\"address\":\"0x...\","
        "\"size\":64}, {\"op\":\"translate\",\"address\":\"0x...\"}, "
        "{\"op\":\"dse_status\"} ] }");
    batch->callback([&context, state, continue_on_error] {
        std::ifstream stream(state->file);
        if (!stream) {
            throw CliError(blook::kdu::Status::not_found,
                           "cannot open batch file: " + state->file);
        }
        nlohmann::json document;
        try {
            stream >> document;
        } catch (const std::exception& error) {
            throw CliError(blook::kdu::Status::invalid_argument,
                           std::string("invalid batch JSON: ") + error.what());
        }
        if (!document.contains("ops") || !document["ops"].is_array()) {
            throw CliError(blook::kdu::Status::invalid_argument,
                           "batch JSON must contain an \"ops\" array");
        }
        auto& session = context.ensure_session();
        nlohmann::json results = nlohmann::json::array();
        bool failed = false;
        for (const auto& operation : document["ops"]) {
            nlohmann::json entry;
            try {
                entry = execute(operation, session);
                entry["status"] = "ok";
            } catch (const CliError& error) {
                failed = true;
                entry = {
                    {"op", operation.value("op", std::string("<unknown>"))},
                    {"status", blook::kdu::status_to_string(error.status())},
                    {"error", error.what()}};
                if (!continue_on_error) {
                    results.push_back(std::move(entry));
                    break;
                }
            }
            results.push_back(std::move(entry));
        }
        if (context.options.json) {
            std::printf("%s\n",
                        nlohmann::json({{"ok", !failed}, {"results", results}})
                            .dump(2)
                            .c_str());
        } else {
            std::vector<std::vector<std::string>> rows = {
                {"Op", "Status", "Details"}};
            for (const auto& entry : results) {
                std::string details;
                for (auto iterator = entry.begin(); iterator != entry.end();
                     ++iterator) {
                    if (iterator.key() == "op" || iterator.key() == "status") {
                        continue;
                    }
                    if (!details.empty()) {
                        details += " ";
                    }
                    details += iterator.key() + "=" + iterator.value().dump();
                }
                rows.push_back({entry.value("op", "?"),
                                entry.value("status", "?"), details});
            }
            std::printf("%s", render_table(rows).c_str());
        }
        if (failed) {
            throw CliError(blook::kdu::Status::partial_write,
                           "batch contains failed operations");
        }
    });
}

}  // namespace blook::kdu::cli
