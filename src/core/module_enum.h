// blook-kdu: kernel module enumeration (no kernel access required).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "blook/kdu/types.h"

namespace blook::kdu::core {

struct KernelModuleEntry {
    std::string name;  // file name, e.g. "ntoskrnl.exe"
    std::string path;  // full path, e.g. "\\SystemRoot\\system32\\ntoskrnl.exe"
    std::uint64_t base = 0;
    std::uint32_t size = 0;
};

// Enumerate loaded kernel modules via NtQuerySystemInformation(
// SystemModuleInformation), the same source Process Explorer uses. Requires no
// privileges.
Result<std::vector<KernelModuleEntry>> enum_kernel_modules();

// Look up one module by case-insensitive file name.
const KernelModuleEntry* find_module(
    const std::vector<KernelModuleEntry>& modules, std::string_view name);

}  // namespace blook::kdu::core
