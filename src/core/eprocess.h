// blook-kdu: locate EPROCESS objects and process PEBs without kernel help.
//
// The driver-only backend cannot call PsLookupProcessByProcessId(), so it uses
// two documented user-mode tricks to bootstrap process memory access:
//   * NtQuerySystemInformation(SystemExtendedHandleInformation) reports the
//     kernel object pointer of every handle the caller owns, which gives the
//     EPROCESS address of a process we hold a handle to;
//   * NtQueryInformationProcess(ProcessBasicInformation) reports the PEB user
//     VA, which is then used to validate the CR3 read from
//     KPROCESS.DirectoryTableBase.
#pragma once

#include <cstdint>
#include <optional>

#include "blook/kdu/types.h"
#include "core/page_table.h"

namespace blook::kdu::core {

// KPROCESS starts EPROCESS, so KPROCESS.DirectoryTableBase is valid at this
// offset for the whole x64 Windows 7..11 range.
constexpr std::uint64_t kEprocessDirectoryTableBaseOffset = 0x28;

// PEB field offsets (x64).
constexpr std::uint64_t kPebImageBaseAddressOffset = 0x10;
constexpr std::uint64_t kPebLdrOffset = 0x18;

struct ProcessAddressSpace {
    std::uint32_t pid = 0;
    std::uint64_t eprocess = 0;    // kernel VA of EPROCESS
    std::uint64_t cr3 = 0;         // validated DirectoryTableBase
    std::uint64_t peb = 0;         // user VA of the PEB
    std::uint64_t image_base = 0;  // from the PEB (0 when unknown)
};

// EPROCESS address for a process we can open a handle to. Returns not_found
// for protected / non-existent processes.
Result<std::uint64_t> find_eprocess(std::uint32_t pid);

// PEB user VA for a process.
Result<std::uint64_t> query_process_peb(std::uint32_t pid);

// Best-effort image base from the PEB (requires PROCESS_VM_READ access).
Result<std::uint64_t> query_process_image_base(std::uint32_t pid);

// Validates a candidate CR3 by translating the PEB and checking that the
// resulting PEB looks real (canonical ImageBaseAddress + Ldr). When
// expected_image is non-zero the PEB image base must match.
bool validate_process_cr3(const PhysicalReadFn& read, std::uint64_t cr3,
                          std::uint64_t peb, std::uint64_t expected_image);

}  // namespace blook::kdu::core
