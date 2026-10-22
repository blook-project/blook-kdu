// blook-kdu: low-stub PML4 discovery unit tests.
#include <iostream>

#include <doctest/doctest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "core/low_stub.h"

namespace {

// Synthetic low memory: 1 MiB, the PROCESSOR_START_BLOCK signature at 0x5000
// plus a valid-looking CR3 in the documented fields.
std::vector<std::uint8_t> make_low_memory(std::uint64_t cr3) {
    std::vector<std::uint8_t> memory(0x100000, 0);
    constexpr std::uint64_t kBlockOffset = 0x5000;
    // jmp rel32 placeholder matching 0x00000001000600E9 & mask
    const std::uint64_t jmp = 0x00000001000600E9ull;
    std::memcpy(memory.data() + kBlockOffset, &jmp, sizeof(jmp));
    const std::uint64_t lm_target = 0xfffff80000000000ull | 0x1000;
    std::memcpy(memory.data() + kBlockOffset + 0x70, &lm_target,
                sizeof(lm_target));
    std::memcpy(memory.data() + kBlockOffset + 0xA0, &cr3, sizeof(cr3));
    return memory;
}

}  // namespace

TEST_CASE("low stub discovery finds the CR3 from the start block") {
    constexpr std::uint64_t kCr3 = 0x1AA000;
    const auto memory = make_low_memory(kCr3);
    blook::kdu::core::PhysicalReadFn read =
        [&memory](std::uint64_t address, void* buffer,
                  std::size_t size) -> blook::kdu::Result<std::size_t> {
        if (address + size > memory.size()) {
            return blook::kdu::Result<std::size_t>::fail(
                blook::kdu::Status::invalid_physical_address,
                "outside synthetic low memory");
        }
        std::memcpy(buffer, memory.data() + address, size);
        return blook::kdu::Result<std::size_t>::ok(size);
    };
    auto result = blook::kdu::core::find_pml4_from_low_stub(read);
    REQUIRE(result.has_value());
    CHECK(result.value() == kCr3);
}

TEST_CASE("low stub discovery reports not_found when the block is absent") {
    std::vector<std::uint8_t> memory(0x100000, 0);
    blook::kdu::core::PhysicalReadFn read =
        [&memory](std::uint64_t address, void* buffer,
                  std::size_t size) -> blook::kdu::Result<std::size_t> {
        if (address + size > memory.size()) {
            return blook::kdu::Result<std::size_t>::fail(
                blook::kdu::Status::invalid_physical_address,
                "outside synthetic low memory");
        }
        std::memcpy(buffer, memory.data() + address, size);
        return blook::kdu::Result<std::size_t>::ok(size);
    };
    auto result = blook::kdu::core::find_pml4_from_low_stub(read);
    CHECK(!result.has_value());
    CHECK(result.error().code == blook::kdu::Status::not_found);
}
