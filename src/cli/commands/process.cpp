// blook-kdu CLI: `process` command group.
//
// Kill-only BYOVD drivers (EDR/AV termination primitives) expose a single
// "terminate this pid" IOCTL and no kernel memory primitive at all. They are
// still first-class exploits, but they cannot feed `mem`/`modules`; this
// command group is how they are driven.
//
// Option storage lives in a shared_ptr state so the CLI11 callbacks, which run
// after add_process_command() returned, never touch destroyed locals.
#include <cstdio>
#include <memory>
#include <string>

#include "cli/commands.h"
#include "cli/output.h"

namespace blook::kdu::cli {
namespace {

struct ProcessState {
    std::string pid;
    std::string exploit;
};

void kill_process(Context& context, const ProcessState& state) {
    if (!state.exploit.empty()) {
        context.options.exploit = state.exploit;
    }
    // Kill-only drivers have no memory primitive, so the payload backend can
    // never be mapped through them: stay on the driver backend explicitly.
    context.options.use_payload = false;

    auto& session = context.ensure_session();
    const auto pid = parse_u32(state.pid);
    auto result = session.terminate_process(pid);
    if (!result) {
        throw CliError(result.error().code, result.error().message);
    }
    if (context.options.json) {
        std::printf("{\"pid\":%u,\"terminated\":true,\"exploit\":\"%s\"}\n",
                    pid, json_escape(session.info().exploit).c_str());
        return;
    }
    std::printf("%s pid %u via %s (%s)\n", green("terminated").c_str(), pid,
                session.info().exploit.c_str(),
                session.info().driver_name.c_str());
}

}  // namespace

void add_process_command(CLI::App& app, Context& context) {
    auto* command = app.add_subcommand(
        "process", "Process primitives provided by kill-only drivers");
    command->require_subcommand(1);

    auto state = std::make_shared<ProcessState>();

    auto* kill = command->add_subcommand(
        "kill", "Terminate a process through a kill-only vulnerable driver");
    kill->add_option("--pid", state->pid, "Target process id")->required();
    kill->add_option("--exploit", state->exploit,
                     "Kill-only exploit id (default: auto-select)");
    kill->callback([&context, state] { kill_process(context, *state); });
}

}  // namespace blook::kdu::cli
