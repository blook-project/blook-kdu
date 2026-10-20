// blook-kdu: manual mapper implementation (stage-2: kernel stage stub driver).
#include "loader/manual_map.h"

#include <cstring>
#include <map>
#include <mutex>
#include <string>

#include "core/kernel_exports.h"
#include "core/log.h"
#include "core/module_enum.h"
#include "core/win32.h"

namespace blook::kdu {
namespace {

// Resolve the loaded ntoskrnl base address on the live system.
Result<std::uint64_t> ntoskrnl_base() {
    auto modules = core::enum_kernel_modules();
    if (!modules) {
        return Result<std::uint64_t>::fail(modules.error().code,
                                           modules.error().message);
    }
    const auto* ntos = core::find_module(modules.value(), "ntoskrnl.exe");
    if (!ntos) {
        return Result<std::uint64_t>::fail(Status::not_found,
                                           "ntoskrnl.exe is not loaded");
    }
    return Result<std::uint64_t>::ok(ntos->base);
}

}  // namespace

// ---------------------------------------------------------------------------
// Image preparation
// ---------------------------------------------------------------------------
Result<PreparedImage> prepare_image(std::span<const std::uint8_t> image) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return Result<PreparedImage>::fail(Status::invalid_image,
                                           "image is too small");
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return Result<PreparedImage>::fail(Status::invalid_image,
                                           "missing DOS signature");
    }
    if (dos->e_lfanew < 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) >
            image.size()) {
        return Result<PreparedImage>::fail(Status::invalid_image,
                                           "bad e_lfanew");
    }
    const auto* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return Result<PreparedImage>::fail(Status::invalid_image,
                                           "missing PE signature");
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        return Result<PreparedImage>::fail(Status::invalid_image,
                                           "image is not x64");
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return Result<PreparedImage>::fail(Status::invalid_image,
                                           "image is not PE32+");
    }
    if ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
        return Result<PreparedImage>::fail(Status::invalid_image,
                                           "kernel image must be a DLL (.sys)");
    }
    if (nt->OptionalHeader.SizeOfImage == 0 ||
        nt->OptionalHeader.SizeOfImage > 0x4000000) {
        return Result<PreparedImage>::fail(Status::invalid_image,
                                           "unreasonable SizeOfImage");
    }

    const auto size_of_image = nt->OptionalHeader.SizeOfImage;
    const auto headers_size = nt->OptionalHeader.SizeOfHeaders;

    PreparedImage prepared;
    prepared.size_of_image = size_of_image;
    prepared.entry_offset = nt->OptionalHeader.AddressOfEntryPoint;
    prepared.preferred_base = nt->OptionalHeader.ImageBase;
    const auto& export_directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_directory.VirtualAddress != 0 &&
        export_directory.VirtualAddress + export_directory.Size <=
            image.size()) {
        const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            image.data() + export_directory.VirtualAddress);
        if (exports->Name != 0 && exports->Name < image.size()) {
            prepared.dll_name =
                reinterpret_cast<const char*>(image.data() + exports->Name);
        }
    }
    prepared.mapped.assign(size_of_image, 0);
    if (headers_size > size_of_image || headers_size > image.size()) {
        return Result<PreparedImage>::fail(Status::invalid_image,
                                           "bad SizeOfHeaders");
    }
    std::memcpy(prepared.mapped.data(), image.data(), headers_size);

    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        const auto& section = sections[index];
        if (section.SizeOfRawData == 0) {
            continue;
        }
        if (static_cast<std::size_t>(section.PointerToRawData) +
                section.SizeOfRawData >
            image.size()) {
            return Result<PreparedImage>::fail(Status::invalid_image,
                                               "section data out of bounds");
        }
        if (section.VirtualAddress + section.SizeOfRawData > size_of_image) {
            return Result<PreparedImage>::fail(Status::invalid_image,
                                               "section exceeds SizeOfImage");
        }
        std::memcpy(prepared.mapped.data() + section.VirtualAddress,
                    image.data() + section.PointerToRawData,
                    section.SizeOfRawData);
    }

    // Collect DIR64 relocations.
    const auto& reloc_directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_directory.VirtualAddress != 0 && reloc_directory.Size != 0) {
        if (reloc_directory.VirtualAddress + reloc_directory.Size >
            size_of_image) {
            return Result<PreparedImage>::fail(Status::invalid_image,
                                               "relocations out of bounds");
        }
        std::size_t cursor = reloc_directory.VirtualAddress;
        const std::size_t end = cursor + reloc_directory.Size;
        while (cursor + sizeof(IMAGE_BASE_RELOCATION) <= end) {
            const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                prepared.mapped.data() + cursor);
            if (block->SizeOfBlock == 0 || cursor + block->SizeOfBlock > end) {
                break;
            }
            const auto count =
                (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                sizeof(WORD);
            const auto* entries =
                reinterpret_cast<const WORD*>(prepared.mapped.data() + cursor +
                                              sizeof(IMAGE_BASE_RELOCATION));
            for (std::size_t index = 0; index < count; ++index) {
                const WORD entry = entries[index];
                const WORD type = entry >> 12;
                const WORD offset = entry & 0x0FFF;
                if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    continue;
                }
                if (type != IMAGE_REL_BASED_DIR64) {
                    return Result<PreparedImage>::fail(
                        Status::invalid_image,
                        "unsupported relocation type " + std::to_string(type));
                }
                const auto rva = block->VirtualAddress + offset;
                if (rva + sizeof(std::uint64_t) > size_of_image) {
                    return Result<PreparedImage>::fail(
                        Status::invalid_image, "relocation out of bounds");
                }
                prepared.relocations.push_back(rva);
            }
            cursor += block->SizeOfBlock;
        }
    }

    // Resolve imports against ntoskrnl. Image base is patched later, so store
    // kernel VAs for now in a side table keyed by the import slot RVA.
    auto ntos = ntoskrnl_base();
    if (!ntos) {
        return Result<PreparedImage>::fail(ntos.error().code,
                                           ntos.error().message);
    }
    auto exports = core::load_kernel_exports(core::system_root() +
                                             "\\System32\\ntoskrnl.exe");
    if (!exports) {
        return Result<PreparedImage>::fail(exports.error().code,
                                           exports.error().message);
    }
    auto& export_map = exports.value();

    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            .VirtualAddress != 0) {
        std::size_t cursor =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                .VirtualAddress;
        while (true) {
            const auto* descriptor =
                reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                    prepared.mapped.data() + cursor);
            if (descriptor->Name == 0) {
                break;
            }
            const std::string module_name = reinterpret_cast<const char*>(
                prepared.mapped.data() + descriptor->Name);
            prepared.imported_modules.push_back(module_name);
            if (_stricmp(module_name.c_str(), "ntoskrnl.exe") != 0 &&
                _stricmp(module_name.c_str(), "hal.dll") != 0 &&
                _stricmp(module_name.c_str(), "ntkrnlmp.exe") != 0) {
                return Result<PreparedImage>::fail(
                    Status::invalid_image,
                    "unsupported import module: " + module_name);
            }
            const auto lookup_rva = descriptor->OriginalFirstThunk
                                        ? descriptor->OriginalFirstThunk
                                        : descriptor->FirstThunk;
            auto* iat = reinterpret_cast<std::uint64_t*>(
                prepared.mapped.data() + descriptor->FirstThunk);
            const auto* lookup = reinterpret_cast<const std::uint64_t*>(
                prepared.mapped.data() + lookup_rva);
            for (std::size_t index = 0; lookup[index] != 0; ++index) {
                if ((lookup[index] & IMAGE_ORDINAL_FLAG64) != 0) {
                    return Result<PreparedImage>::fail(
                        Status::invalid_image,
                        "ordinal imports are not supported");
                }
                const auto* name = reinterpret_cast<const char*>(
                    prepared.mapped.data() + (lookup[index] & 0x7FFFFFFF) + 2);
                auto found = export_map.find(name);
                if (found == export_map.end()) {
                    return Result<PreparedImage>::fail(
                        Status::invalid_image,
                        std::string("unresolved import: ") + name + " from " +
                            module_name);
                }
                iat[index] = ntos.value() + found->second;
            }
            cursor += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    // The exception directory cannot be registered without kernel support; the
    // mapped image must not rely on SEH. Report it so the caller can warn.
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
            .Size != 0) {
        KDU_LOG_DEBUG(
            "image has an exception directory; SEH inside a manually mapped "
            "image is not supported unless the payload registers its table");
    }
    KDU_LOG_INFO("prepared image {} ({} bytes, {} relocations, entry 0x{:x})",
                 prepared.dll_name, prepared.size_of_image,
                 prepared.relocations.size(), prepared.entry_offset);
    return Result<PreparedImage>::ok(std::move(prepared));
}

ManualMapper::ManualMapper(IKernelAccess& access,
                           exploits::IServiceHost& services)
    : access_(access), services_(services) {}

ManualMapper::~ManualMapper() = default;

Result<MappedImage> ManualMapper::map(std::span<const std::uint8_t> image,
                                      const MapOptions& options) {
    (void)image;
    (void)options;
    return Result<MappedImage>::fail(
        Status::not_supported,
        "manual mapping is not wired up yet (stage-1 stub under construction)");
}

Result<void> ManualMapper::unmap(std::uint64_t base) {
    (void)base;
    return Result<void>::fail(Status::not_supported,
                              "unmap is not wired up yet");
}

}  // namespace blook::kdu
