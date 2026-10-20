// blook-kdu CLI: `map` / `unmap` / payload commands.
#include <cstdio>
#include <memory>

#include "cli/commands.h"
#include "cli/output.h"

namespace blook::kdu::cli {
namespace {

struct MapState {
    std::string image;
    std::string name;
    std::string bootstrap_file;
};

}  // namespace

void add_map_command(CLI::App& app, Context& context) {
    auto state = std::make_shared<MapState>();

    auto* map = app.add_subcommand(
        "map", "Manual-map a kernel image (.sys) or the embedded payload");
    bool payload = false;
    bool no_entry = false;
    map->add_option("image", state->image, "Path to a .sys image");
    map->add_flag("--payload", payload,
                  "Map the embedded kernel payload and attach kchannel");
    map->add_option("--name", state->name, "Diagnostic name");
    map->add_option("--bootstrap-file", state->bootstrap_file,
                    "Pass this file's bytes to the entry point");
    map->add_flag("--no-entry", no_entry, "Only map, do not call the entry");
    map->callback([&context, state, payload, no_entry] {
        auto& session = context.ensure_session();
        blook::kdu::MapOptions options;
        options.name = state->name;
        if (!state->bootstrap_file.empty()) {
            options.bootstrap = load_file(state->bootstrap_file);
        }
        options.call_entry = !no_entry;
        blook::kdu::Result<blook::kdu::MappedImage> result =
            blook::kdu::Result<blook::kdu::MappedImage>::fail(
                blook::kdu::Status::invalid_argument, "missing image");
        if (payload) {
            result = session.map_payload(options);
        } else {
            if (state->image.empty()) {
                throw CliError(blook::kdu::Status::invalid_argument,
                               "provide an image path or --payload");
            }
            const auto bytes = load_file(state->image);
            result = session.map_driver(bytes, options);
        }
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        if (context.options.json) {
            std::printf(
                "{\"name\":\"%s\",\"base\":\"%s\",\"size\":%u,"
                "\"entry_status\":%d}\n",
                result->name.c_str(), hex(result->base).c_str(),
                static_cast<unsigned>(result->size),
                static_cast<int>(result->entry_status));
        } else {
            std::printf("%s mapped at %s (%s), entry status 0x%x\n",
                        green("ok").c_str(), hex(result->base).c_str(),
                        human_size(result->size).c_str(),
                        static_cast<unsigned>(result->entry_status));
        }
    });

    auto* unmap = app.add_subcommand("unmap", "Unmap a manually mapped image");
    unmap->add_option("base", state->image, "Image base address")->required();
    unmap->callback([&context, state] {
        auto& session = context.ensure_session();
        auto result = session.unmap(parse_u64(state->image));
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        std::printf("%s\n", green("unmapped").c_str());
    });

    auto* unload_payload =
        app.add_subcommand("unload-payload", "Detach and unload the payload");
    unload_payload->callback([&context] {
        auto& session = context.ensure_session();
        auto result = session.unload_payload();
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        std::printf("%s\n", green("payload unloaded").c_str());
    });
}

}  // namespace blook::kdu::cli
