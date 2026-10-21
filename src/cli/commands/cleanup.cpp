// blook-kdu CLI: `cleanup` and `traces` commands.
#include <cstdio>

#include "cli/commands.h"
#include "cli/output.h"
#include "core/trace.h"

namespace blook::kdu::cli {

void add_cleanup_command(CLI::App& app, Context& context) {
    auto* cleanup = app.add_subcommand(
        "cleanup", "Unload the vulnerable driver and remove traces");
    bool event_log = false;
    bool scan = true;
    cleanup->add_flag("--event-log", event_log,
                      "Also clear the System event log (destructive)");
    cleanup->add_flag("--no-scan", scan, "Skip the post-cleanup trace scan");
    cleanup->callback([&context, event_log, scan] {
        if (!context.session) {
            // Nothing was opened by this invocation; cleanup only makes sense
            // for a live session, so just scan.
            std::vector<std::string> services;
            std::vector<std::string> files;
            for (const auto& remembered : core::remembered_drivers()) {
                services.push_back(remembered.service);
                files.push_back(remembered.path);
            }
            auto report = core::scan_traces(services, files);
            if (!report) {
                throw CliError(report.error().code, report.error().message);
            }
            if (context.options.json) {
                std::printf("%s\n", traces_json(report.value()).c_str());
            } else if (report->findings.empty()) {
                std::printf("%s\n", green("no traces found").c_str());
            } else {
                for (const auto& finding : report->findings) {
                    std::printf("%s %s: %s (%s)\n", red("trace").c_str(),
                                finding.category.c_str(),
                                finding.description.c_str(),
                                finding.location.c_str());
                }
            }
            return;
        }
        blook::kdu::CleanupOptions options;
        options.clean_event_log = event_log;
        options.scan_traces = scan;
        auto result = context.session->cleanup(options);
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        if (context.options.json) {
            std::printf("%s\n", cleanup_json(result.value()).c_str());
            return;
        }
        for (const auto& action : result->actions) {
            std::printf("%s %s\n", green("cleaned").c_str(), action.c_str());
        }
        for (const auto& residual : result->residuals) {
            std::printf("%s %s\n", yellow("residual").c_str(),
                        residual.c_str());
        }
        std::printf("%s\n", result->clean
                                ? green("clean").c_str()
                                : yellow("residual traces remain").c_str());
        context.session.reset();
    });

    auto* traces = app.add_subcommand(
        "traces", "Scan for leftover driver traces (read-only)");
    traces->callback([&context] {
        std::vector<std::string> services;
        std::vector<std::string> files;
        for (const auto& remembered : core::remembered_drivers()) {
            services.push_back(remembered.service);
            files.push_back(remembered.path);
        }
        auto result = core::scan_traces(services, files);
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        if (context.options.json) {
            std::printf("%s\n", traces_json(result.value()).c_str());
            return;
        }
        if (result->findings.empty()) {
            std::printf("%s\n", green("no traces found").c_str());
            return;
        }
        for (const auto& finding : result->findings) {
            std::printf("%s %-9s %s (%s)\n", red("trace").c_str(),
                        finding.category.c_str(), finding.description.c_str(),
                        finding.location.c_str());
        }
    });
}

}  // namespace blook::kdu::cli
