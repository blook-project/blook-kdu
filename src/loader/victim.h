// blook-kdu: victim driver used as the execution trampoline for manual mapping.
//
// Process Explorer's signed driver (PROCEXP152) is loaded as a normal service;
// its dispatch routine prologue is located by signature in the loaded image, a
// 5-byte jump to our kernel stage is written over it (bypassing the read-only
// page via the exploit's physical write primitive), and opening the device
// triggers the stage. The stage image and the target image are both mapped by
// the generic prepare_image() machinery, so imports/relocations are handled in
// user mode.
#pragma once

#include <cstdint>
#include <span>

#include "blook/kdu/types.h"
#include "exploits/common/iexploit.h"

namespace blook::kdu::loader {

constexpr std::uint32_t kVictimResourceId = 9101;
constexpr const char* kVictimDriverFile = "PROCEXP152.sys";
constexpr const char* kVictimServiceName = "PROCEXP152";
constexpr const char* kVictimDeviceName = "\\\\.\\PROCEXP152";

// Metadata used by ServiceHost to stage/load the victim driver.
const exploits::ExploitInfo& victim_info();

// Dispatch routine signature from the Process Explorer driver (same bytes KDU
// uses); matched inside the victim's .text section.
std::span<const std::uint8_t> victim_dispatch_signature();

// The embedded victim driver image (RCDATA).
Result<std::span<const std::uint8_t>> victim_image();

}  // namespace blook::kdu::loader
