// blook-kdu: kernel export table resolution.
#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "blook/kdu/types.h"

namespace blook::kdu::core {

// Parse the export table of a PE file on disk and return name -> RVA.
// Used by the manual mapper: the loaded ntoskrnl base plus an export RVA gives
// the absolute kernel address of any imported function.
Result<std::map<std::string, std::uint32_t>> load_kernel_exports(
    const std::string& path);

}  // namespace blook::kdu::core
