// blook-kdu: embedded driver images (Win32 RCDATA resources).
#pragma once

#include <cstdint>
#include <span>

#include "blook/kdu/types.h"

namespace blook::kdu::core {

// Returns a view of an embedded RCDATA resource. The bytes live in the module
// image and stay valid for the process lifetime.
Result<std::span<const std::uint8_t>> load_embedded_resource(
    std::uint32_t resource_id);

// Convenience: true when the resource exists.
bool has_embedded_resource(std::uint32_t resource_id);

}  // namespace blook::kdu::core
