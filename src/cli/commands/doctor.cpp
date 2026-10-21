// blook-kdu CLI: `doctor` command (environment + trace diagnostics).
#include <cstdio>

#include "cli/commands.h"
#include "cli/output.h"
#include "core/module_enum.h"
#include "core/trace.h"
#include "core/win32.h"
#include "exploits/common/iexploit.h"

namespace blook::kdu::cli {

void add_doctor_command(CLI::App& app, Context& context) {
    auto* doctor =
        app.add_subcommand("doctor", "Check environment and leftover traces");
    bool traces = false;
    bool deep = false;
    doctor->add_flag("--traces", traces, "Scan for leftover driver traces");
    doctor->add_flag("--deep", deep, "Also open a session and verify access");
    doctor->callback([&context, traces, deep] {
        std::vector<std::vector<std::string>> rows = {{"Check", "Result"}};
        bool ok = true;
        const auto build = core::windows_build_number();
        rows.push_back({"Windows build", std::to_string(build)});
        std::string hypervisor;
        const bool under_hypervisor =
            core::is_running_under_hypervisor(&hypervisor);
        const bool vmware_guest =
            under_hypervisor && hypervisor.find("VMware") != std::string::npos;
        rows.push_back(
            {"Hypervisor", under_hypervisor ? hypervisor : "none (host)"});
        rows.push_back({"Kernel ops allowed", vmware_guest
                                                  ? green("yes (VMware guest)")
                                                  : red("no (VM-only guard)")});
        ok = ok && vmware_guest;
        const bool elevated = core::is_process_elevated();
        rows.push_back({"Elevated", elevated ? green("yes") : red("no")});
        ok = ok && elevated;
        rows.push_back(
            {"Exploits compiled in",
             std::to_string(blook::kdu::exploits::all_exploits().size())});

        std::size_t modules = 0;
        auto kernel_modules = core::enum_kernel_modules();
        if (kernel_modules) {
            modules = kernel_modules->size();
            rows.push_back({"Kernel modules visible", std::to_string(modules)});
        } else {
            rows.push_back({"Kernel modules visible",
                            red(kernel_modules.error().message)});
            ok = false;
        }

        if (traces) {
            std::vector<std::string> services;
            std::vector<std::string> files;
            for (const auto& remembered : core::remembered_drivers()) {
                services.push_back(remembered.service);
                files.push_back(remembered.path);
            }
            auto scan = core::scan_traces(services, files);
            if (!scan) {
                rows.push_back({"Trace scan", red(scan.error().message)});
                ok = false;
            } else if (scan->findings.empty()) {
                rows.push_back({"Trace scan", green("clean")});
            } else {
                for (const auto& finding : scan->findings) {
                    rows.push_back(
                        {"Trace: " + finding.category,
                         finding.description + " (" + finding.location + ")"});
                }
                ok = false;
            }
        }

        if (deep) {
            auto opened = blook::kdu::kdu_open();
            if (!opened) {
                rows.push_back({"Kernel access", red(opened.error().message)});
                ok = false;
            } else {
                rows.push_back({"Kernel access",
                                green("ok via " + opened->info().exploit +
                                      " (" + opened->info().backend + ")")});
            }
        }

        if (context.options.json) {
            std::printf("{\"ok\":%s,\"checks\":[", ok ? "true" : "false");
            for (std::size_t index = 1; index < rows.size(); ++index) {
                if (index > 1) {
                    std::printf(",");
                }
                std::printf("{\"name\":\"%s\",\"result\":\"%s\"}",
                            json_escape(rows[index][0]).c_str(),
                            json_escape(rows[index][1]).c_str());
            }
            std::printf("]}\n");
        } else {
            std::printf("%s", render_table(rows).c_str());
        }
        if (!ok) {
            throw CliError(blook::kdu::Status::internal_error,
                           "doctor found problems");
        }
    });
}

}  // namespace blook::kdu::cli
