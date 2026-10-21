// Manual mapper image-preparation tests.
//
// These run on the host without any kernel access: prepare_image() only needs
// the on-disk ntoskrnl.exe (for the export table) and the loaded ntoskrnl base
// (from the system module list), both available to an ordinary user.
#include <iostream>
#include <doctest/doctest.h>

#include <windows.h>

#include <cstring>
#include <vector>

#include "core/module_enum.h"
#include "core/win32.h"
#include "loader/manual_map.h"

using namespace blook::kdu;

namespace {

// Reads the built payload .sys that sits next to this test executable. Returns
// an empty vector when it is not available (e.g. a host-only test build).
std::vector<std::uint8_t> load_payload() {
    const auto payload_path = core::current_process_path();
    const auto directory =
        payload_path.substr(0, payload_path.find_last_of("\\/"));
    const auto candidate = directory + "\\kdu_payload.sys";
    if (!core::file_exists(candidate)) {
        return {};
    }
    auto bytes = core::read_file(candidate);
    if (!bytes) {
        return {};
    }
    return std::move(bytes.value());
}

IMAGE_NT_HEADERS* pe_headers(std::vector<std::uint8_t>& image) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return nullptr;
    }
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) >
            image.size()) {
        return nullptr;
    }
    auto* nt =
        reinterpret_cast<IMAGE_NT_HEADERS*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }
    return nt;
}

// RVA -> file offset through the section table (0 when not mapped).
std::size_t rva_to_file_offset(const std::vector<std::uint8_t>& image,
                               std::uint32_t rva) {
    auto* data = const_cast<std::uint8_t*>(image.data());
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(data);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(data + dos->e_lfanew);
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (USHORT index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        const auto& section = sections[index];
        if (rva >= section.VirtualAddress &&
            rva < section.VirtualAddress + section.SizeOfRawData) {
            return static_cast<std::size_t>(section.PointerToRawData) +
                   (rva - section.VirtualAddress);
        }
    }
    return 0;
}

bool kernel_base_visible() {
    auto modules = core::enum_kernel_modules();
    if (!modules) {
        return false;
    }
    const auto* ntos = core::find_module(modules.value(), "ntoskrnl.exe");
    return ntos != nullptr && ntos->base != 0;
}

}  // namespace

TEST_CASE("prepare_image rejects garbage and truncated images") {
    std::vector<std::uint8_t> garbage(0x200, 0x41);
    auto result = prepare_image(garbage);
    CHECK(!result.has_value());
    CHECK(result.error().code == Status::invalid_image);

    std::vector<std::uint8_t> empty;
    CHECK(!prepare_image(empty).has_value());

    const auto payload = load_payload();
    if (payload.empty()) {
        MESSAGE("skipping truncation tests: kdu_payload.sys not available");
        return;
    }
    for (const std::size_t size :
         {std::size_t{1}, std::size_t{0x10}, std::size_t{0x40},
          std::size_t{0x200}, payload.size() / 2}) {
        std::vector<std::uint8_t> truncated(payload.begin(),
                                            payload.begin() + size);
        auto truncated_result = prepare_image(truncated);
        CHECK(!truncated_result.has_value());
        CHECK(truncated_result.error().code == Status::invalid_image);
    }
}

TEST_CASE("prepare_image rejects malformed headers") {
    auto payload = load_payload();
    if (payload.empty()) {
        MESSAGE("skipping: kdu_payload.sys not available");
        return;
    }
    auto* nt = pe_headers(payload);
    REQUIRE(nt != nullptr);

    {
        auto copy = payload;
        // Re-interpret after copying: the vector may have moved.
        auto* copied_nt = pe_headers(copy);
        REQUIRE(copied_nt != nullptr);
        copied_nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
        auto result = prepare_image(copy);
        CHECK(!result.has_value());
        CHECK(result.error().message.find("x64") != std::string::npos);
    }
    {
        auto copy = payload;
        auto* copied_nt = pe_headers(copy);
        REQUIRE(copied_nt != nullptr);
        copied_nt->OptionalHeader.SizeOfImage = 0;
        CHECK(!prepare_image(copy).has_value());
    }
    {
        auto copy = payload;
        auto* copied_nt = pe_headers(copy);
        REQUIRE(copied_nt != nullptr);
        copied_nt->OptionalHeader.SizeOfImage = 0x8000000;
        CHECK(!prepare_image(copy).has_value());
    }
    {
        auto copy = payload;
        auto* copied_nt = pe_headers(copy);
        REQUIRE(copied_nt != nullptr);
        // Import directory pointing one byte before the end of the image.
        auto& import_directory =
            copied_nt->OptionalHeader
                .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        import_directory.VirtualAddress =
            copied_nt->OptionalHeader.SizeOfImage - 2;
        import_directory.Size = 40;
        auto result = prepare_image(copy);
        CHECK(!result.has_value());
        CHECK(result.error().message.find("import") != std::string::npos);
    }
    {
        auto copy = payload;
        auto* copied_nt = pe_headers(copy);
        REQUIRE(copied_nt != nullptr);
        const auto import_rva = copied_nt->OptionalHeader
                                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                                    .VirtualAddress;
        const auto descriptor_offset = rva_to_file_offset(copy, import_rva);
        REQUIRE(descriptor_offset != 0);
        auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            copy.data() + descriptor_offset);
        // Point the module name at a known-bad string.
        const auto name_offset = rva_to_file_offset(copy, descriptor->Name);
        REQUIRE(name_offset != 0);
        std::memcpy(copy.data() + name_offset, "xtoskrnl.exe", 12);
        auto result = prepare_image(copy);
        CHECK(!result.has_value());
        CHECK(result.error().message.find("unsupported import module") !=
              std::string::npos);
    }
    {
        auto copy = payload;
        auto* copied_nt = pe_headers(copy);
        REQUIRE(copied_nt != nullptr);
        const auto import_rva = copied_nt->OptionalHeader
                                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                                    .VirtualAddress;
        const auto descriptor_offset = rva_to_file_offset(copy, import_rva);
        REQUIRE(descriptor_offset != 0);
        auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            copy.data() + descriptor_offset);
        const auto lookup_rva = descriptor->OriginalFirstThunk
                                    ? descriptor->OriginalFirstThunk
                                    : descriptor->FirstThunk;
        const auto lookup_offset = rva_to_file_offset(copy, lookup_rva);
        REQUIRE(lookup_offset != 0);
        auto* lookup =
            reinterpret_cast<std::uint64_t*>(copy.data() + lookup_offset);
        *lookup |= IMAGE_ORDINAL_FLAG64;
        auto result = prepare_image(copy);
        CHECK(!result.has_value());
        CHECK(result.error().message.find("ordinal") != std::string::npos);
    }
}

TEST_CASE("prepare_image maps and relocates the built kernel payload") {
    const auto payload = load_payload();
    if (payload.empty()) {
        MESSAGE("skipping: kdu_payload.sys not available");
        return;
    }
    // Kernel module base addresses are hidden from unprivileged callers on
    // Windows 11; import resolution is covered by the VM e2e in that case.
    if (!kernel_base_visible()) {
        MESSAGE(
            "skipping import assertions: kernel base hidden (VM-only path)");
        return;
    }
    auto prepared = prepare_image(payload);
    if (!prepared) {
        MESSAGE("prepare_image failed: " << prepared.error().message);
    }
    REQUIRE(prepared.has_value());
    CHECK(prepared->size_of_image > 0);
    CHECK(prepared->entry_offset != 0);
    CHECK(!prepared->relocations.empty());
    CHECK(prepared->preferred_base != 0);
    CHECK(prepared->mapped.size() == prepared->size_of_image);
    CHECK(prepared->imported_modules.size() >= 2);

    const auto* dos =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(prepared->mapped.data());
    CHECK(dos->e_magic == IMAGE_DOS_SIGNATURE);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        prepared->mapped.data() + dos->e_lfanew);
    CHECK(nt->Signature == IMAGE_NT_SIGNATURE);
    CHECK(prepared->entry_offset < nt->OptionalHeader.SizeOfImage);
    CHECK(prepared->has_exception_directory ==
          (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
               .Size != 0));

    // Every import must be patched to an absolute canonical kernel address.
    std::uint64_t patched_slots = 0;
    const auto& import_directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    const auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        prepared->mapped.data() + import_directory.VirtualAddress);
    while (descriptor->Name != 0) {
        const auto* iat = reinterpret_cast<const std::uint64_t*>(
            prepared->mapped.data() + descriptor->FirstThunk);
        for (std::size_t index = 0; iat[index] != 0; ++index) {
            CHECK(iat[index] >= 0xFFFF800000000000ull);
            ++patched_slots;
        }
        ++descriptor;
    }
    CHECK(patched_slots > 0);
}

TEST_CASE("initialize_security_cookie replaces the linker default") {
    auto payload = load_payload();
    if (payload.empty()) {
        MESSAGE("skipping: kdu_payload.sys not available");
        return;
    }
    auto* nt = pe_headers(payload);
    REQUIRE(nt != nullptr);
    // Inject the MSVC default cookie + complement into a writable section so
    // prepare_image detects them. Payload/stage images are built with /GS- and
    // therefore have none of their own.
    constexpr std::uint64_t kDefaultCookie = 0x0000'2B99'2DDF'A232ull;
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    std::size_t writable_offset = 0;
    for (USHORT index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        const auto& section = sections[index];
        if ((section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0 &&
            section.SizeOfRawData >= 0x40) {
            writable_offset = section.PointerToRawData + 0x10;
            break;
        }
    }
    REQUIRE(writable_offset != 0);
    const std::uint64_t complement = ~kDefaultCookie;
    std::memcpy(payload.data() + writable_offset, &kDefaultCookie, 8);
    std::memcpy(payload.data() + writable_offset + 8, &complement, 8);

    auto prepared = prepare_image(payload);
    REQUIRE(prepared.has_value());
    REQUIRE(prepared->security_cookie_offset != 0);
    REQUIRE(prepared->security_cookie_complement_offset != 0);
    constexpr std::uint64_t kTestCookie = 0x1122'3344'5566'7788ull;
    initialize_security_cookie(prepared.value(), kTestCookie);
    std::uint64_t stored = 0;
    std::memcpy(&stored,
                prepared->mapped.data() + prepared->security_cookie_offset, 8);
    CHECK(stored == kTestCookie);
    std::memcpy(
        &stored,
        prepared->mapped.data() + prepared->security_cookie_complement_offset,
        8);
    CHECK(stored == ~kTestCookie);
}

TEST_CASE("prepare_image rejects malformed relocations and sections") {
    auto payload = load_payload();
    if (payload.empty()) {
        MESSAGE("skipping: kdu_payload.sys not available");
        return;
    }
    {
        auto copy = payload;
        auto* nt = pe_headers(copy);
        REQUIRE(nt != nullptr);
        const auto reloc_rva =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                .VirtualAddress;
        REQUIRE(reloc_rva != 0);
        const auto reloc_offset = rva_to_file_offset(copy, reloc_rva);
        REQUIRE(reloc_offset != 0);
        auto* first = reinterpret_cast<IMAGE_BASE_RELOCATION*>(copy.data() +
                                                               reloc_offset);
        REQUIRE(first->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION) + 2);
        auto* entries = reinterpret_cast<WORD*>(copy.data() + reloc_offset +
                                                sizeof(IMAGE_BASE_RELOCATION));
        // Keep the page offset, change the relocation type to HIGHLOW (3),
        // which a x64 kernel image must not contain.
        entries[0] = static_cast<WORD>((3u << 12) | (entries[0] & 0x0FFF));
        auto result = prepare_image(copy);
        CHECK(!result.has_value());
        CHECK(result.error().message.find("relocation") != std::string::npos);
    }
    {
        auto copy = payload;
        auto* nt = pe_headers(copy);
        REQUIRE(nt != nullptr);
        auto* sections = IMAGE_FIRST_SECTION(nt);
        sections[0].SizeOfRawData = 0xFFFFFF;
        auto result = prepare_image(copy);
        CHECK(!result.has_value());
        CHECK(result.error().message.find("section") != std::string::npos);
    }
}
