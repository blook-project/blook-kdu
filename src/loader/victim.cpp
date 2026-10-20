// blook-kdu: victim driver resources and signature.
#include "loader/victim.h"

#include "core/resources.h"
#include "loader/resource.h"

namespace blook::kdu::loader {
namespace {

// Process Explorer dispatch routine prologue (KDU's g_ProcExpSig). The victim
// driver is renamed to PROCEXP152.sys and loaded on demand.
constexpr std::uint8_t kDispatchSignature[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x81, 0xEC, 0x90, 0x00, 0x00,
    0x00, 0x48, 0x8B, 0xFA, 0x33, 0xDB, 0x48, 0x8B, 0xD1, 0x48, 0x8B, 0x8F,
    0xB8, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x47, 0x18, 0x48, 0x89, 0x5F, 0x38,
    0x0F, 0xB6, 0x01, 0x44, 0x8B, 0x49, 0x08, 0x44, 0x8B, 0x51, 0x18, 0x84,
    0xC0, 0x74, 0x3E, 0x3C, 0x0E, 0x74, 0x0A, 0xBB, 0x10, 0x00, 0x00, 0xC0};

}  // namespace

const exploits::ExploitInfo& victim_info() {
    static const exploits::ExploitInfo kInfo = [] {
        exploits::ExploitInfo info{};
        info.id = "victim-procexp";
        info.display_name = "Process Explorer 16 (victim trampoline)";
        info.description =
            "Signed Process Explorer driver used only as the manual-map "
            "execution trampoline";
        info.vendor = "Microsoft Sysinternals";
        info.cve = "";
        info.driver_file = kVictimDriverFile;
        info.service_name = kVictimServiceName;
        info.device_name = "\\\\.\\PROCEXP152";
        info.image_resource_id = kVictimResourceId;
        info.capabilities = exploits::Capability::none;
        info.min_build = 7600;
        info.max_build = 0xFFFF'FFFFu;
        info.unloadable = true;
        return info;
    }();
    return kInfo;
}

std::span<const std::uint8_t> victim_dispatch_signature() {
    return std::span<const std::uint8_t>(kDispatchSignature,
                                         sizeof(kDispatchSignature));
}

Result<std::span<const std::uint8_t>> victim_image() {
    return core::load_embedded_resource(kVictimResourceId);
}

}  // namespace blook::kdu::loader
