// blook-kdu CLI: `dse` command group.
#include <fmt/format.h>

#include <cstdio>
#include <cstring>

#include "cli/commands.h"
#include "cli/output.h"

namespace blook::kdu::cli {

void add_dse_command(CLI::App& app, Context& context) {
    auto* dse =
        app.add_subcommand("dse", "Driver Signature Enforcement control");
    dse->require_subcommand(1);

    auto* status = dse->add_subcommand("status", "Show current DSE state");
    status->callback([&context] {
        auto& session = context.ensure_session();
        auto result = session.dse_status();
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        if (context.options.json) {
            std::printf("%s\n", dse_json(result.value()).c_str());
            return;
        }
        std::vector<std::vector<std::string>> rows = {
            {"Field", "Value"},
            {"DSE", result->enabled ? red("enabled") : green("disabled")},
            {"g_CiOptions", hex(result->options)},
            {"Address", hex(result->options_address)},
        };
        std::printf("%s", render_table(rows).c_str());
    });

    auto* disable =
        dse->add_subcommand("disable", "Disable DSE (g_CiOptions=0)");
    disable->callback([&context] {
        auto& session = context.ensure_session();
        auto result = session.dse_disable();
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        std::printf("%s driver signature enforcement disabled\n",
                    green("ok").c_str());
    });

    auto* restore =
        dse->add_subcommand("restore", "Restore the original DSE state");
    restore->callback([&context] {
        auto& session = context.ensure_session();
        auto result = session.dse_restore();
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        std::printf("%s driver signature enforcement restored\n",
                    green("ok").c_str());
    });

    auto* poke = dse->add_subcommand(
        "poke", "Diagnostic: write a DWORD to a kernel address");
    poke->require_option();
    std::string poke_address;
    std::string poke_value;
    poke->add_option("--address", poke_address, "Kernel VA (hex)")->required();
    poke->add_option("--value", poke_value, "Value (hex)")->required();
    poke->callback([&context, &poke_address, &poke_value] {
        auto& session = context.ensure_session();
        const auto address = parse_u64(poke_address);
        const auto value = parse_u32(poke_value);
        auto written = session.write_virtual(address, &value, sizeof(value));
        if (!written) {
            throw CliError(written.error().code, written.error().message);
        }
        std::uint32_t read_back = 0;
        auto read =
            session.read_virtual(address, &read_back, sizeof(read_back));
        if (!read || read_back != value) {
            throw CliError(blook::kdu::Status::dse_patch_failed,
                           "poke verification failed");
        }
        std::printf("wrote 0x%x at %s (verified)\n", value,
                    hex(address).c_str());
    });
    auto* scan = dse->add_subcommand(
        "scan", "List plausible g_CiOptions store targets in ci.dll");
    scan->callback([&context] {
        auto& session = context.ensure_session();
        auto modules = session.enum_modules();
        if (!modules) {
            throw CliError(modules.error().code, modules.error().message);
        }
        const blook::kdu::ModuleInfo* ci = nullptr;
        for (const auto& module : modules.value()) {
            if (_stricmp(module.name.c_str(), "ci.dll") == 0) {
                ci = &module;
                break;
            }
        }
        if (!ci) {
            throw CliError(blook::kdu::Status::dse_not_found,
                           "ci.dll is not loaded");
        }
        std::uint8_t headers[0x1000] = {};
        auto read = session.read_virtual(ci->base, headers, sizeof(headers));
        if (!read) {
            throw CliError(read.error().code, read.error().message);
        }
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers);
        const auto* nt =
            reinterpret_cast<const IMAGE_NT_HEADERS*>(headers + dos->e_lfanew);
        const auto image_size = nt->OptionalHeader.SizeOfImage;
        auto image = session.read_virtual_bytes(ci->base, image_size);
        if (!image) {
            throw CliError(image.error().code, image.error().message);
        }
        struct Candidate {
            std::uint64_t address = 0;
            std::uint32_t value = 0;
            std::string section;
        };
        std::vector<Candidate> candidates;
        const auto* sections = IMAGE_FIRST_SECTION(nt);
        for (USHORT index = 0; index < nt->FileHeader.NumberOfSections;
             ++index) {
            const auto& section = sections[index];
            if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
                continue;
            }
            const std::size_t start = section.VirtualAddress;
            const std::size_t size = std::min<std::size_t>(
                section.Misc.VirtualSize, image->size() - start);
            for (std::size_t offset = 0; offset + 6 <= size; ++offset) {
                const auto* code = image->data() + start + offset;
                // Store forms that can update a global DWORD:
                //   89 /r  mov dword ptr [rip+rel32], reg (len 6)
                //   C7 05  mov dword ptr [rip+rel32], imm32 (len 10)
                //   83 /r  op dword ptr [rip+rel32], imm8 (len 7)
                //   81 /r  op dword ptr [rip+rel32], imm32 (len 10)
                std::size_t instruction_length = 0;
                if (code[0] == 0x89 && (code[1] & 0xC7) == 0x05) {
                    instruction_length = 6;
                } else if (code[0] == 0xC7 && code[1] == 0x05) {
                    instruction_length = 10;
                } else if ((code[0] == 0x83 || code[0] == 0x81) &&
                           (code[1] & 0xC7) == 0x05) {
                    instruction_length = code[0] == 0x83 ? 7 : 10;
                }
                if (instruction_length == 0 ||
                    offset + instruction_length > size) {
                    continue;
                }
                std::int32_t relative = 0;
                std::memcpy(&relative, code + 2, sizeof(relative));
                const std::int64_t target =
                    static_cast<std::int64_t>(start) +
                    static_cast<std::int64_t>(offset) +
                    static_cast<std::int64_t>(instruction_length) + relative;
                if (target <= 0 ||
                    static_cast<std::uint64_t>(target) >= image_size) {
                    continue;
                }
                const auto address = ci->base + target;
                std::uint32_t value = 0;
                auto value_read =
                    session.read_virtual(address, &value, sizeof(value));
                if (!value_read) {
                    continue;
                }
                Candidate candidate;
                candidate.address = address;
                candidate.value = value;
                char name[9] = {};
                std::memcpy(name, section.Name, 8);
                candidate.section = name;
                candidates.push_back(std::move(candidate));
            }
        }
        if (context.options.json) {
            std::printf("{\"ci_base\":\"%s\",\"candidates\":[",
                        hex(ci->base).c_str());
            for (std::size_t index = 0; index < candidates.size(); ++index) {
                if (index) {
                    std::printf(",");
                }
                std::printf(
                    "{\"address\":\"%s\",\"value\":\"0x%x\","
                    "\"section\":\"%s\"}",
                    hex(candidates[index].address).c_str(),
                    candidates[index].value,
                    json_escape(candidates[index].section).c_str());
            }
            std::printf("]}\n");
            return;
        }
        std::vector<std::vector<std::string>> rows = {
            {"Address", "Value", "Section"}};
        for (const auto& candidate : candidates) {
            rows.push_back({hex(candidate.address),
                            "0x" + fmt::format("{:x}", candidate.value),
                            candidate.section});
        }
        std::printf("%s", render_table(rows).c_str());
    });
}

}  // namespace blook::kdu::cli
