// blook-kdu CLI: command registration.
#pragma once

#include <CLI/CLI.hpp>

#include "cli/context.h"

namespace blook::kdu::cli {

void add_info_command(CLI::App& app, Context& context);
void add_exploits_command(CLI::App& app, Context& context);
void add_mem_command(CLI::App& app, Context& context);
void add_map_command(CLI::App& app, Context& context);
void add_dse_command(CLI::App& app, Context& context);
void add_modules_command(CLI::App& app, Context& context);
void add_doctor_command(CLI::App& app, Context& context);
void add_cleanup_command(CLI::App& app, Context& context);
void add_batch_command(CLI::App& app, Context& context);
void add_assets_command(CLI::App& app, Context& context);
void add_payload_command(CLI::App& app, Context& context);
void add_process_command(CLI::App& app, Context& context);

}  // namespace blook::kdu::cli
