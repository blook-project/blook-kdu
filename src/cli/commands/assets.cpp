// blook-kdu CLI: `assets` command.
//
// Verifies that every exploit's embedded driver image (Win32 RCDATA resource)
// is a complete, valid x64 PE that can actually be staged. This runs with no
// kernel access, so it is safe on hosts and is part of CI.
#include <cstdio>
#include <memory>

#include "cli/commands.h"
#include "cli/output.h"
#include "core/resources.h"
#include "exploits/common/iexploit.h"

namespace blook::kdu::cli {
namespace {

struct AssetStatus {
    std::string id;
    std::uint32_t resource_id = 0;
    std::size_t size = 0;
    bool ok = false;
    std::string detail;
};

AssetStatus verify_asset(const blook::kdu::exploits::ExploitInfo& info) {
    AssetStatus status;
    status.id = std::string(info.id);
    status.resource_id = info.image_resource_id;
    auto image = core::load_embedded_resource(info.image_resource_id);
    if (!image) {
        status.detail = image.error().message;
        return status;
    }
    status.size = image->size();
    if (image->size() < sizeof(IMAGE_DOS_HEADER)) {
        status.detail = "image smaller than a DOS header";
        return status;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image->data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        status.detail = "missing MZ signature";
        return status;
    }
    if (dos->e_lfanew < 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) >
            image->size()) {
        status.detail = "broken e_lfanew";
        return status;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image->data() +
                                                               dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        status.detail = "missing PE signature";
        return status;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        status.detail = "not an x64 image";
        return status;
    }
    if (nt->OptionalHeader.SizeOfImage == 0) {
        status.detail = "SizeOfImage is zero";
        return status;
    }
    status.ok = true;
    status.detail = "valid PE, SizeOfImage=" +
                    std::to_string(nt->OptionalHeader.SizeOfImage);
    return status;
}

}  // namespace

void add_assets_command(CLI::App& app, Context& context) {
    auto* assets = app.add_subcommand(
        "assets", "Verify embedded exploit driver images (no kernel access)");
    assets->require_subcommand(1);
    auto* verify = assets->add_subcommand(
        "verify", "Check every embedded driver image is a valid x64 PE");
    verify->callback([&context] {
        std::vector<AssetStatus> statuses;
        bool ok = true;
        for (const auto& descriptor : blook::kdu::exploits::all_exploits()) {
            auto status = verify_asset(descriptor.info());
            ok = ok && status.ok;
            statuses.push_back(std::move(status));
        }
        if (context.options.json) {
            std::printf("{\"ok\":%s,\"assets\":[", ok ? "true" : "false");
            for (std::size_t index = 0; index < statuses.size(); ++index) {
                if (index) {
                    std::printf(",");
                }
                std::printf(
                    "{\"id\":\"%s\",\"resource\":%u,\"size\":%zu,"
                    "\"ok\":%s,\"detail\":\"%s\"}",
                    statuses[index].id.c_str(), statuses[index].resource_id,
                    statuses[index].size, statuses[index].ok ? "true" : "false",
                    json_escape(statuses[index].detail).c_str());
            }
            std::printf("]}\n");
        } else {
            std::vector<std::vector<std::string>> rows = {
                {"ID", "Resource", "Size", "Status", "Detail"}};
            for (const auto& status : statuses) {
                rows.push_back({status.id, std::to_string(status.resource_id),
                                std::to_string(status.size),
                                status.ok ? green("ok") : red("invalid"),
                                status.detail});
            }
            std::printf("%s", render_table(rows).c_str());
        }
        if (!ok) {
            throw CliError(blook::kdu::Status::invalid_image,
                           "one or more embedded driver images are invalid");
        }
    });
}

}  // namespace blook::kdu::cli
