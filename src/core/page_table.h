// blook-kdu: x64 page-table walker.
//
// Works on top of "physical memory read/write" callbacks, so it can be used
// both by the driver backend (vulnerable driver primitives) and by the payload
// backend (kernel MmCopyMemory). It is deliberately free of any Windows API
// dependency so unit tests can build synthetic page tables and verify the
// translation logic (4 KiB / 2 MiB / 1 GiB pages, non-present entries).
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "blook/kdu/types.h"

namespace blook::kdu::core {

// Callbacks return the number of bytes transferred, or an error.
using PhysicalReadFn = std::function<Result<std::size_t>(
    std::uint64_t address, void* buffer, std::size_t size)>;
using PhysicalWriteFn = std::function<Result<std::size_t>(
    std::uint64_t address, const void* buffer, std::size_t size)>;

// One resolved page-table translation.
struct Translation {
    std::uint64_t physical = 0;
    std::uint64_t span = 0;  // 0x1000, 0x200000 or 0x40000000
    std::uint64_t virtual_address = 0;
};

constexpr std::uint64_t kPageSize = 0x1000;
constexpr std::uint64_t kLargePageSize = 0x200000;
constexpr std::uint64_t kHugePageSize = 0x40000000;
constexpr std::uint64_t kPhysicalAddressMask = 0x000F'FFFF'FFFF'F000ull;

bool is_canonical_address(std::uint64_t address);

// Walks the page tables of one address space. `pml4_physical` is the value of
// CR3 with the low flag bits masked off by the caller.
class PageTableWalker {
   public:
    PageTableWalker(std::uint64_t pml4_physical, PhysicalReadFn read,
                    PhysicalWriteFn write = {})
        : pml4_(pml4_physical & kPhysicalAddressMask),
          read_(std::move(read)),
          write_(std::move(write)) {}

    [[nodiscard]] std::uint64_t pml4() const noexcept { return pml4_; }

    // Translate one virtual address. Returns the physical address and the size
    // of the page the address lives in (4 KiB, 2 MiB or 1 GiB).
    Result<Translation> translate(std::uint64_t virtual_address) const;

    // Strict multi-page read: fails as soon as one page cannot be translated.
    Result<std::size_t> read(std::uint64_t virtual_address, void* buffer,
                             std::size_t size) const;

    // Tolerant read used for module dumping: unmapped pages are zero-filled and
    // reported in *bytes_valid (which may be null).
    Result<std::size_t> read_tolerant(std::uint64_t virtual_address,
                                      void* buffer, std::size_t size,
                                      std::size_t* bytes_valid = nullptr) const;

    // Strict multi-page write.
    Result<std::size_t> write(std::uint64_t virtual_address, const void* buffer,
                              std::size_t size) const;

    // Read a POD value from a kernel virtual address.
    template <typename T>
    Result<T> read_value(std::uint64_t virtual_address) const {
        T value{};
        auto result = read(virtual_address, &value, sizeof(value));
        if (!result) {
            return Result<T>::fail(result.error().code, result.error().message);
        }
        return Result<T>::ok(value);
    }

    template <typename T>
    Result<void> write_value(std::uint64_t virtual_address,
                             const T& value) const {
        auto result = write(virtual_address, &value, sizeof(value));
        if (!result) {
            return Result<void>::fail(result.error().code,
                                      result.error().message);
        }
        return Result<void>::ok();
    }

    [[nodiscard]] bool writable() const noexcept {
        return static_cast<bool>(write_);
    }

   private:
    std::uint64_t pml4_ = 0;
    PhysicalReadFn read_;
    PhysicalWriteFn write_;
};

}  // namespace blook::kdu::core
