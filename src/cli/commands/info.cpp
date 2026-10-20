// blook-kdu CLI: `info` command.
#include <cstdio>

#include "cli/commands.h"
#include "cli/output.h"
#include "core/win32.h"

namespace blook::kdu::cli {

void add_info_command(CLI::App& app, Context& context) {
    auto* command =
        app.add_subcommand("info", "Show exploit/backend/session information");
    command->callback([&context] {
        auto& session = context.ensure_session();
        const auto& info = session.info();
        if (context.options.json) {
            std::printf("%s\n", session_info_json(info).c_str());
            return;
        }
        std::printf("%s %s\n", bold("blook-kdu").c_str(), info.version.c_str());
        std::vector<std::vector<std::string>> rows = {
            {"Field", "Value"},
            {"Windows", core::windows_version_string() + " (build " +
                            std::to_string(info.windows_build) + ")"},
            {"Exploit", info.exploit},
            {"Driver", info.driver_name},
            {"Service", info.service_name},
            {"Backend", info.backend},
            {"Payload", info.payload_mapped
                            ? "mapped at " + hex(info.payload_base) + " (" +
                                  human_size(info.payload_size) + ")"
                            : "not mapped"},
            {"Capabilities",
             [&] {
                 std::string joined;
                 for (const auto& capability : info.capabilities) {
                     if (!joined.empty()) {
                         joined += ", ";
                     }
                     joined += capability;
                 }
                 return joined;
             }()},
        };
        std::printf("%s", render_table(rows).c_str());
    });
}

}  // namespace blook::kdu::cli
