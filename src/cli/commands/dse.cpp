// blook-kdu CLI: `dse` command group.
#include <cstdio>

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
}

}  // namespace blook::kdu::cli
