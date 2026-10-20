// blook-kdu: x64 page-table walker implementation.
#include "core/page_table.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace blook::kdu::core {
namespace {

constexpr std::uint64_t kPml4IndexShift = 39;
constexpr std::uint64_t kPdptIndexShift = 30;
constexpr std::uint64_t kPdIndexShift = 21;
constexpr std::uint64_t kPtIndexShift = 12;

constexpr std::uint64_t kEntryPresent = 0x1;
constexpr std::uint64_t kEntryLargePage = 0x80;

std::uint64_t index_of(std::uint64_t address, std::uint64_t shift) {
    return (address >> shift) & 0x1FF;
}

}  // namespace

bool is_canonical_address(std::uint64_t address) {
    const std::uint64_t high = address >> 47;
    return high == 0 || high == 0x1FFFF;
}

Result<Translation> PageTableWalker::translate(
    std::uint64_t virtual_address) const {
    if (!is_canonical_address(virtual_address)) {
        return Result<Translation>::fail(Status::address_translation_failed,
                                         "non-canonical virtual address");
    }

    std::uint64_t entry = 0;
    std::size_t bytes = 0;
    auto read_entry = [&](std::uint64_t physical,
                          std::uint64_t* value) -> bool {
        auto result = read_(physical, value, sizeof(*value));
        if (!result) {
            return false;
        }
        return result.value() == sizeof(*value);
    };

    // PML4
    if (!read_entry(pml4_ + 8 * index_of(virtual_address, kPml4IndexShift),
                    &entry)) {
        return Result<Translation>::fail(Status::address_translation_failed,
                                         "failed to read PML4 entry");
    }
    if (!(entry & kEntryPresent)) {
        return Result<Translation>::fail(Status::address_translation_failed,
                                         "PML4 entry not present");
    }

    // PDPT
    if (!read_entry((entry & kPhysicalAddressMask) +
                        8 * index_of(virtual_address, kPdptIndexShift),
                    &entry)) {
        return Result<Translation>::fail(Status::address_translation_failed,
                                         "failed to read PDPT entry");
    }
    if (!(entry & kEntryPresent)) {
        return Result<Translation>::fail(Status::address_translation_failed,
                                         "PDPT entry not present");
    }
    if (entry & kEntryLargePage) {  // 1 GiB
        Translation translation;
        translation.physical = (entry & 0x000F'FFFF'C000'0000ull) +
                               (virtual_address & (kHugePageSize - 1));
        translation.span = kHugePageSize;
        translation.virtual_address = virtual_address;
        return Result<Translation>::ok(translation);
    }

    // PD
    if (!read_entry((entry & kPhysicalAddressMask) +
                        8 * index_of(virtual_address, kPdIndexShift),
                    &entry)) {
        return Result<Translation>::fail(Status::address_translation_failed,
                                         "failed to read PD entry");
    }
    if (!(entry & kEntryPresent)) {
        return Result<Translation>::fail(Status::address_translation_failed,
                                         "PD entry not present");
    }
    if (entry & kEntryLargePage) {  // 2 MiB
        Translation translation;
        translation.physical = (entry & 0x000F'FFFF'FFE0'0000ull) +
                               (virtual_address & (kLargePageSize - 1));
        translation.span = kLargePageSize;
        translation.virtual_address = virtual_address;
        return Result<Translation>::ok(translation);
    }

    // PT
    if (!read_entry((entry & kPhysicalAddressMask) +
                        8 * index_of(virtual_address, kPtIndexShift),
                    &entry)) {
        return Result<Translation>::fail(Status::address_translation_failed,
                                         "failed to read PT entry");
    }
    if (!(entry & kEntryPresent)) {
        return Result<Translation>::fail(Status::address_translation_failed,
                                         "PT entry not present");
    }

    Translation translation;
    translation.physical =
        (entry & kPhysicalAddressMask) + (virtual_address & (kPageSize - 1));
    translation.span = kPageSize;
    translation.virtual_address = virtual_address;
    return Result<Translation>::ok(translation);
}

Result<std::size_t> PageTableWalker::read(std::uint64_t virtual_address,
                                          void* buffer,
                                          std::size_t size) const {
    auto* out = static_cast<std::uint8_t*>(buffer);
    std::size_t done = 0;
    while (done < size) {
        const std::uint64_t current = virtual_address + done;
        auto translation = translate(current);
        if (!translation) {
            return Result<std::size_t>::fail(
                translation.error().code,
                translation.error().message + " @ " +
                    std::to_string(static_cast<unsigned long long>(current)));
        }
        const std::uint64_t in_page =
            translation->span - (current & (translation->span - 1));
        const auto take = static_cast<std::size_t>(
            std::min<std::uint64_t>(in_page, size - done));
        auto result = read_(translation->physical, out + done, take);
        if (!result) {
            return Result<std::size_t>::fail(result.error().code,
                                             result.error().message);
        }
        if (result.value() != take) {
            return Result<std::size_t>::fail(Status::partial_read,
                                             "short physical read");
        }
        done += take;
    }
    return Result<std::size_t>::ok(done);
}

Result<std::size_t> PageTableWalker::read_tolerant(
    std::uint64_t virtual_address, void* buffer, std::size_t size,
    std::size_t* bytes_valid) const {
    auto* out = static_cast<std::uint8_t*>(buffer);
    std::size_t done = 0;
    std::size_t valid = 0;
    while (done < size) {
        const std::uint64_t current = virtual_address + done;
        const auto translation = translate(current);
        if (translation) {
            const std::uint64_t in_page =
                translation->span - (current & (translation->span - 1));
            const auto take = static_cast<std::size_t>(
                std::min<std::uint64_t>(in_page, size - done));
            auto result = read_(translation->physical, out + done, take);
            if (result && result.value() == take) {
                done += take;
                valid += take;
                continue;
            }
        }
        // Zero-fill the rest of the current 4 KiB page and continue.
        const std::uint64_t in_page = kPageSize - (current & (kPageSize - 1));
        const auto step = static_cast<std::size_t>(
            std::min<std::uint64_t>(in_page, size - done));
        std::memset(out + done, 0, step);
        done += step;
    }
    if (bytes_valid) {
        *bytes_valid = valid;
    }
    return Result<std::size_t>::ok(valid);
}

Result<std::size_t> PageTableWalker::write(std::uint64_t virtual_address,
                                           const void* buffer,
                                           std::size_t size) const {
    if (!write_) {
        return Result<std::size_t>::fail(Status::not_supported,
                                         "page-table walker is read-only");
    }
    const auto* in = static_cast<const std::uint8_t*>(buffer);
    std::size_t done = 0;
    while (done < size) {
        const std::uint64_t current = virtual_address + done;
        auto translation = translate(current);
        if (!translation) {
            return Result<std::size_t>::fail(
                translation.error().code,
                translation.error().message + " @ " +
                    std::to_string(static_cast<unsigned long long>(current)));
        }
        const std::uint64_t in_page =
            translation->span - (current & (translation->span - 1));
        const auto take = static_cast<std::size_t>(
            std::min<std::uint64_t>(in_page, size - done));
        auto result = write_(translation->physical, in + done, take);
        if (!result) {
            return Result<std::size_t>::fail(result.error().code,
                                             result.error().message);
        }
        if (result.value() != take) {
            return Result<std::size_t>::fail(Status::partial_write,
                                             "short physical write");
        }
        done += take;
    }
    return Result<std::size_t>::ok(done);
}

}  // namespace blook::kdu::core
