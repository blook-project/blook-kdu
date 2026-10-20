// blook-kdu: kernel export table resolution implementation.
#include "core/kernel_exports.h"

#include <windows.h>

#include <cstring>
#include <vector>

#include "core/win32.h"

namespace blook::kdu::core {

Result<std::map<std::string, std::uint32_t>> load_kernel_exports(
    const std::string& path) {
    auto file = read_file(path);
    if (!file) {
        return Result<std::map<std::string, std::uint32_t>>::fail(
            file.error().code, file.error().message);
    }
    const auto& data = file.value();
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) {
        return Result<std::map<std::string, std::uint32_t>>::fail(
            Status::invalid_image, "PE file is too small");
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) >
            data.size()) {
        return Result<std::map<std::string, std::uint32_t>>::fail(
            Status::invalid_image, "not a PE file: " + path);
    }
    const auto* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(data.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return Result<std::map<std::string, std::uint32_t>>::fail(
            Status::invalid_image, "PE32+ signature missing: " + path);
    }
    const auto& directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory.VirtualAddress == 0 || directory.Size == 0) {
        return Result<std::map<std::string, std::uint32_t>>::fail(
            Status::not_found, "PE file has no export table: " + path);
    }
    // Translate the export directory RVA to a file offset via the sections.
    auto rva_to_offset = [&](std::uint32_t rva) -> std::uint64_t {
        const auto* sections = IMAGE_FIRST_SECTION(nt);
        for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
            const auto& section = sections[index];
            if (rva >= section.VirtualAddress &&
                rva < section.VirtualAddress +
                          std::max<std::uint32_t>(section.Misc.VirtualSize,
                                                  section.SizeOfRawData)) {
                const auto delta = rva - section.VirtualAddress;
                if (delta >= section.SizeOfRawData) {
                    return 0;
                }
                return static_cast<std::uint64_t>(section.PointerToRawData) +
                       delta;
            }
        }
        return 0;
    };
    const auto export_offset = rva_to_offset(directory.VirtualAddress);
    if (export_offset == 0 ||
        export_offset + sizeof(IMAGE_EXPORT_DIRECTORY) > data.size()) {
        return Result<std::map<std::string, std::uint32_t>>::fail(
            Status::invalid_image, "bad export directory: " + path);
    }
    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        data.data() + export_offset);
    const auto names_offset = rva_to_offset(exports->AddressOfNames);
    const auto ordinals_offset = rva_to_offset(exports->AddressOfNameOrdinals);
    const auto functions_offset = rva_to_offset(exports->AddressOfFunctions);
    if (names_offset == 0 || ordinals_offset == 0 || functions_offset == 0) {
        return Result<std::map<std::string, std::uint32_t>>::fail(
            Status::invalid_image, "bad export arrays: " + path);
    }
    const auto* names =
        reinterpret_cast<const DWORD*>(data.data() + names_offset);
    const auto* ordinals =
        reinterpret_cast<const WORD*>(data.data() + ordinals_offset);
    const auto* functions =
        reinterpret_cast<const DWORD*>(data.data() + functions_offset);
    std::map<std::string, std::uint32_t> result;
    for (DWORD index = 0; index < exports->NumberOfNames; ++index) {
        const auto name_offset = rva_to_offset(names[index]);
        if (name_offset == 0 || name_offset >= data.size()) {
            continue;
        }
        const char* name =
            reinterpret_cast<const char*>(data.data() + name_offset);
        result.emplace(name, functions[ordinals[index]]);
    }
    return Result<std::map<std::string, std::uint32_t>>::ok(std::move(result));
}

}  // namespace blook::kdu::core
