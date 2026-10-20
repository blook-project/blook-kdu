// blook-kdu: DSE (Driver Signature Enforcement) control.
//
// DSE is implemented by ci.dll: `g_CiOptions` holds the current flags, zero
// disables driver signature enforcement. The address is recovered without
// symbols, the same way KDU does it: ci.dll!CiInitialize jumps to
// CipInitialize, and CipInitialize contains a `mov dword ptr [rip+rel32], ecx`
// that targets g_CiOptions. Both the export table and the instruction bytes are
// read through the kernel memory backend, so no on-disk image is required.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "blook/kdu/types.h"
#include "core/module_enum.h"
#include "exploits/common/kernel_access.h"

namespace blook::kdu::sdk {

struct CiOptionsLocation {
    std::uint64_t address = 0;  // kernel VA of g_CiOptions
    std::uint64_t ci_base = 0;  // ci.dll loaded base
    std::string method;         // how it was found (diagnostics)
};

// Locate g_CiOptions in the currently loaded ci.dll.
Result<CiOptionsLocation> find_ci_options(
    IKernelAccess& access, const std::vector<core::KernelModuleEntry>& modules);

// Read/write the g_CiOptions dword.
Result<std::uint32_t> read_ci_options(IKernelAccess& access,
                                      std::uint64_t address);
Result<void> write_ci_options(IKernelAccess& access, std::uint64_t address,
                              std::uint32_t value);

}  // namespace blook::kdu::sdk
