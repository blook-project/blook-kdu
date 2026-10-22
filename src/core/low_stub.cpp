// blook-kdu: PML4 discovery from the low stub.
#include "core/low_stub.h"

#include <cstring>

namespace blook::kdu::core {
namespace {

// PROCESSOR_START_BLOCK layout on x64 (documented by several public
// references and stable across Windows 7..11):
//   +0x000  E9 xx xx xx xx        jmp to the real-mode startup routine
//   +0x070  self-referencing LM target (nt!KiSystemStartup vicinity)
//   +0x0A0  CR3
constexpr std::uint64_t kStartBlockJmpSignature = 0x00000001000600E9ull;
constexpr std::uint64_t kStartBlockJmpMask = 0xFFFFFFFFFFFF00FFull;
constexpr std::uint64_t kStartBlockLmOffset = 0x70;
constexpr std::uint64_t kStartBlockLmSignature = 0xfffff80000000000ull;
constexpr std::uint64_t kStartBlockLmMask = 0xfffff80000000003ull;
constexpr std::uint64_t kStartBlockCr3Offset = 0xA0;
constexpr std::uint64_t kStartBlockCr3Mask = 0xffffff0000000fffull;

constexpr std::uint64_t kScanStart = 0x1000;
constexpr std::uint64_t kScanEnd = 0x100000;

}  // namespace

Result<std::uint64_t> find_pml4_from_low_stub(const PhysicalReadFn& read) {
    if (!read) {
        return Result<std::uint64_t>::fail(Status::invalid_argument,
                                           "no physical read callback");
    }
    std::uint8_t block[0x1000];
    std::uint8_t probe[sizeof(std::uint64_t)];
    for (std::uint64_t offset = kScanStart; offset < kScanEnd;
         offset += sizeof(block)) {
        // Byte-granular drivers (TPwSav, some I/O-port drivers) turn one block
        // read into 4096 IOCTLs, which made the full 1 MiB scan take millions
        // of round trips. Probe the 8-byte jump signature first and only fetch
        // the whole page once it matches.
        auto probe_result = read(offset, probe, sizeof(probe));
        if (!probe_result) {
            continue;
        }
        std::uint64_t jmp = 0;
        std::memcpy(&jmp, probe, sizeof(jmp));
        if ((jmp & kStartBlockJmpMask) != kStartBlockJmpSignature) {
            continue;
        }
        auto result = read(offset, block, sizeof(block));
        if (!result) {
            continue;
        }
        std::uint64_t lm_target = 0;
        std::memcpy(&lm_target, block + kStartBlockLmOffset, sizeof(lm_target));
        if ((lm_target & kStartBlockLmMask) != kStartBlockLmSignature) {
            continue;
        }
        std::uint64_t cr3 = 0;
        std::memcpy(&cr3, block + kStartBlockCr3Offset, sizeof(cr3));
        if ((cr3 & kStartBlockCr3Mask) != 0 || cr3 == 0) {
            continue;
        }
        return Result<std::uint64_t>::ok(cr3);
    }
    return Result<std::uint64_t>::fail(Status::not_found,
                                       "PROCESSOR_START_BLOCK not found");
}

}  // namespace blook::kdu::core
