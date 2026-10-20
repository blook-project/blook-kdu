// Page-table walker unit tests with synthetic page tables.
#include <doctest/doctest.h>

#include <cstring>
#include <map>
#include <memory>
#include <vector>

#include "core/page_table.h"

using namespace blook::kdu;
using namespace blook::kdu::core;

namespace {

// A tiny fake physical address space backed by a map of 4 KiB frames.
class FakePhysicalMemory {
   public:
    FakePhysicalMemory() {
        read_fn = [this](std::uint64_t address, void* buffer,
                         std::size_t size) {
            return read(address, buffer, size);
        };
        write_fn = [this](std::uint64_t address, const void* buffer,
                          std::size_t size) {
            return write(address, buffer, size);
        };
    }

    void* page(std::uint64_t physical) { return frame(physical); }

    Result<std::size_t> read(std::uint64_t address, void* buffer,
                             std::size_t size) {
        auto* out = static_cast<std::uint8_t*>(buffer);
        std::size_t done = 0;
        while (done < size) {
            const std::uint64_t current = address + done;
            auto* frame_ptr =
                static_cast<std::uint8_t*>(frame(current & ~0xFFFull));
            const auto offset = current & 0xFFF;
            const auto take = static_cast<std::size_t>(
                std::min<std::uint64_t>(0x1000 - offset, size - done));
            std::memcpy(out + done, frame_ptr + offset, take);
            done += take;
        }
        return Result<std::size_t>::ok(done);
    }

    Result<std::size_t> write(std::uint64_t address, const void* buffer,
                              std::size_t size) {
        const auto* in = static_cast<const std::uint8_t*>(buffer);
        std::size_t done = 0;
        while (done < size) {
            const std::uint64_t current = address + done;
            auto* frame_ptr =
                static_cast<std::uint8_t*>(frame(current & ~0xFFFull));
            const auto offset = current & 0xFFF;
            const auto take = static_cast<std::size_t>(
                std::min<std::uint64_t>(0x1000 - offset, size - done));
            std::memcpy(frame_ptr + offset, in + done, take);
            done += take;
        }
        return Result<std::size_t>::ok(done);
    }

    PhysicalReadFn read_fn;
    PhysicalWriteFn write_fn;

   private:
    void* frame(std::uint64_t base) {
        auto found = frames.find(base);
        if (found == frames.end()) {
            auto page = std::make_unique<std::uint8_t[]>(0x1000);
            std::memset(page.get(), 0, 0x1000);
            found = frames.emplace(base, std::move(page)).first;
        }
        return found->second.get();
    }

    std::map<std::uint64_t, std::unique_ptr<std::uint8_t[]>> frames;
};

// Build a 4-level page table mapping `virtual_address` -> `physical_address`.
void map_page(FakePhysicalMemory& memory, std::uint64_t pml4,
              std::uint64_t virtual_address, std::uint64_t physical_address,
              bool large_page = false) {
    auto entry = [&](std::uint64_t table, std::uint64_t index) {
        return static_cast<std::uint64_t*>(memory.page(table)) + index;
    };
    const auto pml4_index = (virtual_address >> 39) & 0x1FF;
    const auto pdpt_index = (virtual_address >> 30) & 0x1FF;
    const auto pd_index = (virtual_address >> 21) & 0x1FF;
    const auto pt_index = (virtual_address >> 12) & 0x1FF;
    const std::uint64_t pdpt = 0x10000;
    const std::uint64_t pd = 0x11000;
    const std::uint64_t pt = 0x12000;
    *entry(pml4, pml4_index) = pdpt | 1;
    *entry(pdpt, pdpt_index) = pd | 1;
    if (large_page) {
        *entry(pd, pd_index) = (physical_address & ~0x1FFFFFull) | 1 | 0x80;
    } else {
        *entry(pd, pd_index) = pt | 1;
        *entry(pt, pt_index) = (physical_address & ~0xFFFull) | 1;
    }
}

}  // namespace

TEST_CASE("translate 4KiB page") {
    FakePhysicalMemory memory;
    constexpr std::uint64_t kPml4 = 0x1000;
    constexpr std::uint64_t kVirtual = 0xFFFF800000001234ull;
    constexpr std::uint64_t kPhysical = 0x5000;
    map_page(memory, kPml4, kVirtual, kPhysical);
    PageTableWalker walker(kPml4, memory.read_fn, memory.write_fn);
    auto translation = walker.translate(kVirtual);
    REQUIRE(translation.has_value());
    CHECK(translation->span == kPageSize);
    CHECK(translation->physical == kPhysical + 0x234);
}

TEST_CASE("translate 2MiB page") {
    FakePhysicalMemory memory;
    constexpr std::uint64_t kPml4 = 0x1000;
    constexpr std::uint64_t kVirtual = 0xFFFF800040001234ull;
    map_page(memory, kPml4, kVirtual, 0x200000, true);
    PageTableWalker walker(kPml4, memory.read_fn, memory.write_fn);
    auto translation = walker.translate(kVirtual);
    REQUIRE(translation.has_value());
    CHECK(translation->span == kLargePageSize);
}

TEST_CASE("non-present entry fails") {
    FakePhysicalMemory memory;
    PageTableWalker walker(0x1000, memory.read_fn, memory.write_fn);
    auto translation = walker.translate(0xFFFF800000001000ull);
    CHECK(!translation.has_value());
    CHECK(translation.error().code == Status::address_translation_failed);
}

TEST_CASE("non-canonical address is rejected") {
    FakePhysicalMemory memory;
    PageTableWalker walker(0x1000, memory.read_fn, memory.write_fn);
    auto translation = walker.translate(0x0000800000000000ull);
    CHECK(!translation.has_value());
}

TEST_CASE("multi-page read and write") {
    FakePhysicalMemory memory;
    constexpr std::uint64_t kPml4 = 0x1000;
    constexpr std::uint64_t kVirtual = 0xFFFF800000010000ull;
    map_page(memory, kPml4, kVirtual, 0x30000);
    map_page(memory, kPml4, kVirtual + kPageSize, 0x31000);
    PageTableWalker walker(kPml4, memory.read_fn, memory.write_fn);
    std::vector<std::uint8_t> pattern(kPageSize + 0x123);
    for (std::size_t index = 0; index < pattern.size(); ++index) {
        pattern[index] = static_cast<std::uint8_t>(index & 0xFF);
    }
    auto written =
        walker.write(kVirtual + 0x7FF, pattern.data(), pattern.size());
    REQUIRE(written.has_value());
    std::vector<std::uint8_t> read_back(pattern.size(), 0);
    auto read =
        walker.read(kVirtual + 0x7FF, read_back.data(), read_back.size());
    REQUIRE(read.has_value());
    CHECK(read_back == pattern);
}

TEST_CASE("tolerant read zero-fills unmapped pages") {
    FakePhysicalMemory memory;
    PageTableWalker walker(0x1000, memory.read_fn, memory.write_fn);
    std::vector<std::uint8_t> buffer(0x100, 0xAA);
    std::size_t valid = 0;
    auto result = walker.read_tolerant(0xFFFF800000002000ull, buffer.data(),
                                       buffer.size(), &valid);
    REQUIRE(result.has_value());
    CHECK(valid == 0);
    CHECK(buffer.front() == 0);
}

TEST_CASE("read-only walker rejects writes") {
    FakePhysicalMemory memory;
    PageTableWalker walker(0x1000, memory.read_fn);
    std::uint64_t value = 0;
    auto result = walker.write(0xFFFF800000000000ull, &value, sizeof(value));
    CHECK(!result.has_value());
    CHECK(result.error().code == Status::not_supported);
}
