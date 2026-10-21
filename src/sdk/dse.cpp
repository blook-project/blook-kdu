// blook-kdu: DSE control implementation.
#include "sdk/dse.h"

#include <cstdlib>
#include <cstring>

#include "core/log.h"
#include "core/win32.h"

namespace blook::kdu::sdk {
namespace {

struct SectionRange {
    std::string name;
    std::uint64_t virtual_address = 0;  // RVA
    std::uint64_t size = 0;
    std::uint32_t characteristics = 0;
};

struct ImageLayout {
    std::uint64_t base = 0;
    std::uint32_t size_of_image = 0;
    std::vector<SectionRange> sections;
};

// Read `size` bytes of kernel memory in page-sized pieces. Returns the number
// of bytes that could be read; unreadable pages are left zeroed.
std::size_t read_image_bytes(IKernelAccess& access, std::uint64_t address,
                             void* buffer, std::size_t size) {
    auto* out = static_cast<std::uint8_t*>(buffer);
    std::size_t valid = 0;
    for (std::size_t offset = 0; offset < size; offset += 0x1000) {
        const auto chunk = std::min<std::size_t>(0x1000, size - offset);
        auto result =
            access.read_virtual(address + offset, out + offset, chunk);
        if (result) {
            valid += result.value();
        }
    }
    return valid;
}

Result<ImageLayout> parse_layout(IKernelAccess& access,
                                 const core::KernelModuleEntry& module) {
    std::uint8_t headers[0x1000] = {};
    auto read = access.read_virtual(module.base, headers, sizeof(headers));
    if (!read) {
        return Result<ImageLayout>::fail(read.error().code,
                                         read.error().message);
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > sizeof(headers)) {
        return Result<ImageLayout>::fail(Status::invalid_image,
                                         "ci.dll has no valid PE header");
    }
    const auto* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(headers + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return Result<ImageLayout>::fail(Status::invalid_image,
                                         "ci.dll has no PE signature");
    }
    ImageLayout layout;
    layout.base = module.base;
    layout.size_of_image = nt->OptionalHeader.SizeOfImage;
    const auto* section = IMAGE_FIRST_SECTION(nt);
    for (USHORT index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        char section_name[9] = {};
        std::memcpy(section_name, section[index].Name, 8);
        layout.sections.push_back(SectionRange{
            section_name, section[index].VirtualAddress,
            section[index].Misc.VirtualSize, section[index].Characteristics});
    }
    return Result<ImageLayout>::ok(std::move(layout));
}

bool in_section(const ImageLayout& layout, std::uint64_t rva,
                std::uint32_t wanted_characteristics) {
    for (const auto& section : layout.sections) {
        if ((section.characteristics & wanted_characteristics) == 0) {
            continue;
        }
        if (rva >= section.virtual_address &&
            rva < section.virtual_address + section.size) {
            return true;
        }
    }
    return false;
}

// Scan a code buffer for an `E8 rel32` call whose destination lies inside the
// image; used to find CiInitialize -> CipInitialize.
std::uint64_t find_call_target(const std::uint8_t* code, std::size_t size,
                               std::uint32_t base_rva,
                               std::uint64_t image_size) {
    for (std::size_t offset = 0; offset + 5 <= size; ++offset) {
        if (code[offset] != 0xE8) {
            continue;
        }
        std::int32_t relative = 0;
        std::memcpy(&relative, code + offset + 1, sizeof(relative));
        const std::int64_t target = static_cast<std::int64_t>(base_rva) +
                                    static_cast<std::int64_t>(offset) + 5 +
                                    relative;
        if (target > 0 && static_cast<std::uint64_t>(target) < image_size) {
            return static_cast<std::uint64_t>(target);
        }
    }
    return 0;
}

// Scan for `89 0D rel32` (mov dword ptr [rip+rel32], ecx) whose destination is
// a writable data address inside the image.
std::uint64_t find_ci_options_in(const std::uint8_t* code, std::size_t size,
                                 std::uint32_t base_rva,
                                 const ImageLayout& layout) {
    for (std::size_t offset = 0; offset + 6 <= size; ++offset) {
        if (!(code[offset] == 0x89 && code[offset + 1] == 0x0D)) {
            continue;
        }
        std::int32_t relative = 0;
        std::memcpy(&relative, code + offset + 2, sizeof(relative));
        const std::int64_t target = static_cast<std::int64_t>(base_rva) +
                                    static_cast<std::int64_t>(offset) + 6 +
                                    relative;
        if (target <= 0) {
            continue;
        }
        const auto rva = static_cast<std::uint64_t>(target);
        if (rva >= layout.size_of_image) {
            continue;
        }
        if (!in_section(layout, rva, IMAGE_SCN_MEM_WRITE)) {
            continue;
        }
        return layout.base + rva;
    }
    return 0;
}

}  // namespace

namespace {

std::string dse_state_path() {
    return std::string(std::getenv("TEMP") ? std::getenv("TEMP")
                                           : "C:\\Windows\\Temp") +
           "\\blook-kdu-dse.txt";
}

}  // namespace

void save_dse_original(std::uint64_t address, std::uint32_t value) {
    const std::string text =
        std::to_string(address) + " " + std::to_string(value) + "\n";
    (void)core::write_file(dse_state_path(), text.data(), text.size());
}

bool load_dse_original(std::uint64_t* address, std::uint32_t* value) {
    if (!address || !value) {
        return false;
    }
    auto contents = core::read_file(dse_state_path());
    if (!contents || contents->empty()) {
        return false;
    }
    std::string text(contents->begin(), contents->end());
    char* end = nullptr;
    const unsigned long long parsed_address =
        std::strtoull(text.c_str(), &end, 10);
    if (end == text.c_str()) {
        return false;
    }
    const auto parsed_value = std::strtoul(end, &end, 10);
    *address = parsed_address;
    *value = static_cast<std::uint32_t>(parsed_value);
    return *address != 0;
}

void clear_dse_original() {
    (void)core::remove_file(dse_state_path());
}

Result<std::uint32_t> read_ci_options(IKernelAccess& access,
                                      std::uint64_t address) {
    return access.read_virtual_value<std::uint32_t>(address);
}

Result<void> write_ci_options(IKernelAccess& access, std::uint64_t address,
                              std::uint32_t value) {
    const auto written = access.write_virtual(address, &value, sizeof(value));
    if (!written) {
        return Result<void>::fail(written.error().code,
                                  written.error().message);
    }
    const auto verify = read_ci_options(access, address);
    if (!verify || verify.value() != value) {
        return Result<void>::fail(Status::dse_patch_failed,
                                  "g_CiOptions write verification failed");
    }
    return Result<void>::ok();
}

Result<CiOptionsLocation> find_ci_options(
    IKernelAccess& access,
    const std::vector<core::KernelModuleEntry>& modules) {
    const core::KernelModuleEntry* ci = nullptr;
    const core::KernelModuleEntry* ntos = nullptr;
    for (const auto& module : modules) {
        if (auto name = module.name; name.size() >= 6) {
            if (_stricmp(name.c_str(), "ci.dll") == 0) {
                ci = &module;
            } else if (_stricmp(name.c_str(), "ntoskrnl.exe") == 0) {
                ntos = &module;
            }
        }
    }
    if (!ci) {
        return Result<CiOptionsLocation>::fail(Status::dse_not_found,
                                               "ci.dll is not loaded");
    }
    auto layout = parse_layout(access, *ci);
    if (!layout) {
        return Result<CiOptionsLocation>::fail(layout.error().code,
                                               layout.error().message);
    }

    // Read the code sections into memory. ci.dll is small (<2 MiB).
    const std::size_t image_size = layout->size_of_image;
    std::vector<std::uint8_t> image(image_size, 0);
    read_image_bytes(access, ci->base, image.data(), image_size);

    // Locate the export table and the CiInitialize RVA.
    std::uint32_t ci_initialize_rva = 0;
    {
        std::uint8_t headers[0x1000] = {};
        std::memcpy(headers, image.data(),
                    std::min<std::size_t>(sizeof(headers), image.size()));
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers);
        const auto* nt =
            reinterpret_cast<const IMAGE_NT_HEADERS*>(headers + dos->e_lfanew);
        const auto& directory =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (directory.VirtualAddress != 0 && directory.Size != 0) {
            const auto export_rva = directory.VirtualAddress;
            const auto* exports =
                reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(image.data() +
                                                                export_rva);
            const auto* names = reinterpret_cast<const DWORD*>(
                image.data() + exports->AddressOfNames);
            const auto* ordinals = reinterpret_cast<const WORD*>(
                image.data() + exports->AddressOfNameOrdinals);
            const auto* functions = reinterpret_cast<const DWORD*>(
                image.data() + exports->AddressOfFunctions);
            for (DWORD index = 0; index < exports->NumberOfNames; ++index) {
                const char* name =
                    reinterpret_cast<const char*>(image.data() + names[index]);
                if (std::strcmp(name, "CiInitialize") == 0) {
                    ci_initialize_rva = functions[ordinals[index]];
                    break;
                }
            }
        }
    }

    CiOptionsLocation location;
    location.ci_base = ci->base;

    auto scan_code = [&](std::uint32_t rva, std::size_t window) {
        if (rva == 0 || rva >= image_size) {
            return std::uint64_t{0};
        }
        const auto available = std::min<std::size_t>(window, image_size - rva);
        return find_ci_options_in(image.data() + rva, available, rva, *layout);
    };

    if (ci_initialize_rva != 0) {
        const auto window =
            std::min<std::size_t>(256, image_size - ci_initialize_rva);
        const auto cip_rva =
            find_call_target(image.data() + ci_initialize_rva, window,
                             ci_initialize_rva, image_size);
        if (cip_rva != 0) {
            location.address =
                scan_code(static_cast<std::uint32_t>(cip_rva), 256);
            if (location.address != 0) {
                location.method = "CiInitialize -> CipInitialize -> mov";
                return Result<CiOptionsLocation>::ok(location);
            }
        }
    }

    // Fallback: scan every executable section for the store instruction.
    for (const auto& section : layout->sections) {
        if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }
        const auto start = section.virtual_address;
        const auto size = std::min<std::uint64_t>(
            section.size, image_size - std::min(start, image_size));
        location.address = find_ci_options_in(
            image.data() + start, static_cast<std::size_t>(size),
            static_cast<std::uint32_t>(start), *layout);
        if (location.address != 0) {
            location.method = "section scan (fallback)";
            return Result<CiOptionsLocation>::ok(location);
        }
    }
    (void)ntos;
    return Result<CiOptionsLocation>::fail(
        Status::dse_not_found,
        "g_CiOptions store instruction not found in ci.dll");
}

Result<std::vector<CiOptionsCandidate>> scan_ci_options(
    IKernelAccess& access,
    const std::vector<core::KernelModuleEntry>& modules) {
    const core::KernelModuleEntry* ci = nullptr;
    for (const auto& module : modules) {
        if (_stricmp(module.name.c_str(), "ci.dll") == 0) {
            ci = &module;
            break;
        }
    }
    if (!ci) {
        return Result<std::vector<CiOptionsCandidate>>::fail(
            Status::dse_not_found, "ci.dll is not loaded");
    }
    auto layout = parse_layout(access, *ci);
    if (!layout) {
        return Result<std::vector<CiOptionsCandidate>>::fail(
            layout.error().code, layout.error().message);
    }
    std::vector<std::uint8_t> image(layout->size_of_image, 0);
    read_image_bytes(access, ci->base, image.data(), image.size());

    std::vector<CiOptionsCandidate> candidates;
    for (const auto& section : layout->sections) {
        if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }
        const auto start = static_cast<std::size_t>(section.virtual_address);
        const auto size = static_cast<std::size_t>(
            std::min<std::uint64_t>(section.size, image.size() - start));
        for (std::size_t offset = 0; offset + 6 <= size; ++offset) {
            const auto* code = image.data() + start + offset;
            if (!(code[0] == 0x89 && code[1] == 0x0D)) {
                continue;
            }
            std::int32_t relative = 0;
            std::memcpy(&relative, code + 2, sizeof(relative));
            const std::int64_t target = static_cast<std::int64_t>(start) +
                                        static_cast<std::int64_t>(offset) + 6 +
                                        relative;
            if (target <= 0 ||
                static_cast<std::uint64_t>(target) >= layout->size_of_image) {
                continue;
            }
            const auto rva = static_cast<std::uint64_t>(target);
            if (!in_section(*layout, rva, IMAGE_SCN_MEM_WRITE)) {
                continue;
            }
            CiOptionsCandidate candidate;
            candidate.address = layout->base + rva;
            auto value =
                access.read_virtual_value<std::uint32_t>(candidate.address);
            if (!value) {
                continue;
            }
            candidate.value = value.value();
            for (const auto& containing : layout->sections) {
                if (rva >= containing.virtual_address &&
                    rva < containing.virtual_address + containing.size) {
                    candidate.section = containing.name;
                    break;
                }
            }
            bool duplicate = false;
            for (const auto& existing : candidates) {
                if (existing.address == candidate.address) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                candidates.push_back(std::move(candidate));
            }
        }
    }
    return Result<std::vector<CiOptionsCandidate>>::ok(std::move(candidates));
}

}  // namespace blook::kdu::sdk
