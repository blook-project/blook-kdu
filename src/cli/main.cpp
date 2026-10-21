// blook-kdu CLI entry point.
#include <CLI/CLI.hpp>
#include <fmt/format.h>

#include <io.h>

#include <cstdio>
#include <string>
#include <vector>
#include <cstdlib>
#include <string>

#include "blook/kdu/kdu.h"
#include "blook/kdu/version.h"
#include "cli/commands.h"
#include "cli/context.h"
#include "cli/output.h"
#include "core/win32.h"
#include "exploits/common/iexploit.h"

namespace {

bool stdout_is_terminal() {
    return ::_isatty(::_fileno(stdout)) != 0;
}

bool env_truthy(const char* name) {
    const char* value = std::getenv(name);
    return value != nullptr && *value != '\0' && std::string(value) != "0";
}

// Stable process exit codes for scripting. 0 = success, 1 = generic failure,
// 2 = bad usage, and one code per error class after that.
int exit_code_for(blook::kdu::Status status) {
    using blook::kdu::Status;
    switch (status) {
        case Status::ok:
            return 0;
        case Status::invalid_argument:
            return 2;
        case Status::access_denied:
            return 3;
        case Status::not_found:
            return 4;
        case Status::not_supported:
            return 5;
        case Status::timeout:
            return 6;
        case Status::busy:
            return 7;
        case Status::already_exists:
            return 8;
        case Status::no_memory:
            return 9;
        case Status::io_error:
            return 10;
        case Status::partial_read:
        case Status::partial_write:
            return 11;
        case Status::driver_load_failed:
            return 12;
        case Status::no_suitable_exploit:
            return 13;
        case Status::mapping_failed:
            return 14;
        case Status::payload_unavailable:
            return 15;
        case Status::auth_failed:
            return 16;
        default:
            return 1;
    }
}
void print_error(const blook::kdu::cli::Context& context,
                 blook::kdu::Status status, const std::string& message) {
    if (context.options.json) {
        std::printf("{\"error\":{\"code\":\"%s\",\"message\":\"%s\"}}\n",
                    blook::kdu::status_to_string(status),
                    blook::kdu::cli::json_escape(message).c_str());
    } else {
        std::fprintf(stderr, "%s %s\n", blook::kdu::cli::red("error").c_str(),
                     message.c_str());
    }
}

}  // namespace

int main(int argc, char** argv) {
    blook::kdu::cli::Context context;
    try {
        context.options.color = stdout_is_terminal() && !env_truthy("NO_COLOR");
        blook::kdu::cli::set_color_enabled(context.options.color);

        CLI::App app{
            "blook-kdu - self-contained Windows driver exploitation toolkit"};
        app.set_version_flag("--version,-V", BLOOK_KDU_VERSION_STRING);
        app.require_subcommand(1);
        app.footer(
            "Examples:\n"
            "  kdu exploits list\n"
            "  kdu exploits probe gdrv\n"
            "  kdu --exploit gdrv info\n"
            "  kdu mem virt read 0xfffff80000000000 64\n"
            "  kdu mem process read --pid 1234 0x7ff7a0000000 32\n"
            "  kdu dse status | kdu map --payload | kdu modules\n"
            "  kdu --json modules > modules.json\n"
            "  kdu batch ops.json\n"
            "Exit codes: 0 ok, 2 usage, 3 access, 4 not found, 5 unsupported, "
            "6 timeout, 10 io, 13 no exploit, 14 mapping, 15 payload.");

        app.add_flag("--json", context.options.json,
                     "Machine readable JSON output");
        app.add_flag("-v,--verbose", context.options.verbose,
                     "Verbose logging");
        app.add_option("--exploit", context.options.exploit,
                       "Force a specific exploit id (see 'kdu exploits list')");
        bool no_payload = false;
        app.add_flag("--no-payload", no_payload,
                     "Do not map the kernel payload; use the driver backend");
        app.add_flag("--driver-only", context.options.driver_only,
                     "Only use driver primitives (implies --no-payload)");
        app.add_option("--log-level", context.options.log_level,
                       "spdlog level: trace|debug|info|warn|error|off");
        app.add_option("--timeout", context.options.timeout_ms,
                       "Operation timeout in milliseconds");

        blook::kdu::cli::add_info_command(app, context);
        blook::kdu::cli::add_exploits_command(app, context);
        blook::kdu::cli::add_mem_command(app, context);
        blook::kdu::cli::add_map_command(app, context);
        blook::kdu::cli::add_dse_command(app, context);
        blook::kdu::cli::add_modules_command(app, context);
        blook::kdu::cli::add_doctor_command(app, context);
        blook::kdu::cli::add_cleanup_command(app, context);
        blook::kdu::cli::add_batch_command(app, context);
        blook::kdu::cli::add_assets_command(app, context);

        // Allow the global switches before or after the subcommand: strip them
        // from argv and apply them ourselves so `kdu doctor --json` works too.
        std::vector<char*> filtered_args;
        filtered_args.push_back(argv[0]);
        for (int index = 1; index < argc; ++index) {
            const std::string argument = argv[index];
            if (argument == "--json") {
                context.options.json = true;
            } else if (argument == "-v" || argument == "--verbose") {
                context.options.verbose = true;
            } else {
                filtered_args.push_back(argv[index]);
            }
        }
        const int filtered_argc = static_cast<int>(filtered_args.size());

        int exit_code = 0;
        try {
            if (context.options.verbose &&
                context.options.log_level == "warn") {
                context.options.log_level = "debug";
            }
            if (context.options.driver_only || no_payload) {
                context.options.use_payload = false;
            }
            app.parse(filtered_argc, filtered_args.data());
        } catch (const CLI::ParseError& error) {
            return app.exit(error);
        } catch (const blook::kdu::cli::CliError& error) {
            print_error(context, error.status(), error.what());
            exit_code = exit_code_for(error.status());
        } catch (const std::exception& error) {
            print_error(context, blook::kdu::Status::internal_error,
                        error.what());
            exit_code = exit_code_for(blook::kdu::Status::internal_error);
        }

        context.close_session();
        return exit_code;
    } catch (const std::exception& error) {
        print_error(context, blook::kdu::Status::internal_error,
                    std::string("unhandled exception: ") + error.what());
        return 2;
    } catch (...) {
        std::fprintf(stderr, "UNCAUGHT-EXC: unknown\n");
        return 3;
    }
}
