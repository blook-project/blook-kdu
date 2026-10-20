// blook-kdu CLI: `modules` and `dump-driver` commands.
#include <algorithm>
#include <cstdio>
#include <memory>

#include "cli/commands.h"
#include "cli/output.h"

namespace blook::kdu::cli {
namespace {

struct ModulesState {
    std::string filter;
    std::string module;
    std::string output;
};

}  // namespace

void add_modules_command(CLI::App& app, Context& context) {
    auto state = std::make_shared<ModulesState>();

    auto* command = app.add_subcommand("modules", "List loaded kernel modules");
    command->add_option("--filter", state->filter,
                        "Only show names containing text");
    command->callback([&context, state] {
        auto& session = context.ensure_session();
        auto result = session.enum_modules();
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        std::vector<blook::kdu::ModuleInfo> modules = result.value();
        if (!state->filter.empty()) {
            modules.erase(
                std::remove_if(modules.begin(), modules.end(),
                               [&state](const blook::kdu::ModuleInfo& info) {
                                   return info.name.find(state->filter) ==
                                          std::string::npos;
                               }),
                modules.end());
        }
        if (context.options.json) {
            std::printf("%s\n", modules_json(modules).c_str());
            return;
        }
        std::vector<std::vector<std::string>> rows = {
            {"Module", "Base", "Size", "Path"}};
        for (const auto& module : modules) {
            rows.push_back({module.name, hex(module.base),
                            human_size(module.size), module.path});
        }
        std::printf("%s", render_table(rows).c_str());
        std::printf("%s\n",
                    dim(std::to_string(modules.size()) + " modules").c_str());
    });

    auto* dump =
        app.add_subcommand("dump-driver", "Dump a loaded kernel module image");
    bool from_disk = false;
    dump->add_option("module", state->module, "Module name, e.g. ntoskrnl.exe")
        ->required();
    dump->add_option("-o,--output", state->output,
                     "Output file (default: <module>.bin)");
    dump->add_flag("--from-disk", from_disk, "Read the on-disk image instead");
    dump->callback([&context, state, from_disk] {
        auto& session = context.ensure_session();
        blook::kdu::DumpOptions options;
        options.module = state->module;
        options.from_disk = from_disk;
        auto result = session.dump_driver(options);
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        const auto path =
            state->output.empty() ? state->module + ".bin" : state->output;
        save_file(path, result.value());
        std::printf("dumped %s to %s\n", human_size(result->size()).c_str(),
                    path.c_str());
    });
}

}  // namespace blook::kdu::cli
