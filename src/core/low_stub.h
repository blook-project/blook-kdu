// blook-kdu: PML4 discovery from the low stub (PROCESSOR_START_BLOCK).
#pragma once

#include <cstdint>

#include "blook/kdu/types.h"
#include "core/page_table.h"

namespace blook::kdu::core {

// Scans the first MiB of physical memory for the PROCESSOR_START_BLOCK that
// ntoskrnl keeps around on x64 and returns its CR3 (PML4 physical address).
// This is the only way to obtain a page-table root when the vulnerable driver
// offers nothing but physical memory access and no translate primitive.
Result<std::uint64_t> find_pml4_from_low_stub(const PhysicalReadFn& read);

}  // namespace blook::kdu::core
