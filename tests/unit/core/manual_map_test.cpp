// Manual mapper image-preparation tests.
//
// These run on the host without any kernel access: prepare_image() only needs
// the on-disk ntoskrnl.exe (for the export table) and the loaded ntoskrnl base
// (from NtQuerySystemInformation), both available to an ordinary user.
#include <doctest/doctest.h>

#include <windows.h>

#include <vector>

#include "core/win32.h"
#include "loader/manual_map.h"

using namespace blook::kdu;

TEST_CASE("prepare_image rejects garbage") {
    std::vector<std::uint8_t> garbage(0x200, 0x41);
    auto result = prepare_image(garbage);
    CHECK(!result.has_value());
    CHECK(result.error().code == Status::invalid_image);

    std::vector<std::uint8_t> empty;
    auto empty_result = prepare_image(empty);
    CHECK(!empty_result.has_value());
}

TEST_CASE("prepare_image maps and relocates the built kernel payload") {
    // The payload .sys is a sibling of this test executable in the build dir.
    const auto payload_path = core::current_process_path();
    const auto directory = payload_path.substr(0, payload_path.find_last_of("\\/"));
    const auto candidate = directory + "\\kdu_payload.sys";
    if (!core::file_exists(candidate)) {
        MESSAGE("skipping: kdu_payload.sys not next to the test executable");
        return;
    }
    auto bytes = core::read_file(candidate);
    REQUIRE(bytes.has_value());
    auto prepared = prepare_image(bytes.value());
    if (!prepared) {
        MESSAGE("prepare_image failed: " << prepared.error().message);
    }
    REQUIRE(prepared.has_value());
    CHECK(prepared->size_of_image > 0);
    CHECK(prepared->entry_offset != 0);
    CHECK(!prepared->relocations.empty());
    CHECK(prepared->preferred_base != 0);
    CHECK(prepared->mapped.size() == prepared->size_of_image);

    // The mapped layout must carry a valid DOS/NT header and the entry point
    // must point inside .text.
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(
        prepared->mapped.data());
    CHECK(dos->e_magic == IMAGE_DOS_SIGNATURE);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        prepared->mapped.data() + dos->e_lfanew);
    CHECK(nt->Signature == IMAGE_NT_SIGNATURE);
    CHECK(prepared->entry_offset < nt->OptionalHeader.SizeOfImage);

    // Imports of the payload are resolved to absolute kernel addresses: every
    // patched IAT slot must be a canonical kernel pointer for at least one
    // entry (the payload imports ExAllocatePool* / Ps* / Mm* from ntoskrnl).
    std::uint64_t kernel_pointer_count = 0;
    const auto import_rva =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            .VirtualAddress;
    if (import_rva != 0) {
        const auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
            prepared->mapped.data() + import_rva);
        while (descriptor->Name != 0) {
            auto* iat = reinterpret_cast<const std::uint64_t*>(
                prepared->mapped.data() + descriptor->FirstThunk);
            for (std::size_t index = 0; iat[index] != 0; ++index) {
                if (iat[index] >= 0xFFFF800000000000ull) {
                    ++kernel_pointer_count;
                }
            }
            ++descriptor;
        }
    }
    CHECK(kernel_pointer_count > 0);
}
