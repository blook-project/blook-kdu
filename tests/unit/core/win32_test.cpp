// Windows helper unit tests.
#include <doctest/doctest.h>

#include "core/win32.h"

using namespace blook::kdu;
using namespace blook::kdu::core;

TEST_CASE("utf8 / utf16 round trip") {
    const std::wstring wide = L"blook-kdu \u4e2d\u6587 test";
    const auto utf8 = to_utf8(wide);
    CHECK(!utf8.empty());
    CHECK(to_utf16(utf8) == wide);
}

TEST_CASE("win32 status mapping") {
    CHECK(win32_status(ERROR_SUCCESS) == Status::ok);
    CHECK(win32_status(ERROR_ACCESS_DENIED) == Status::access_denied);
    CHECK(win32_status(ERROR_FILE_NOT_FOUND) == Status::not_found);
    CHECK(win32_status(ERROR_INVALID_PARAMETER) == Status::invalid_argument);
    CHECK(nt_status_status(static_cast<LONG>(0xC0000022ul)) ==
          Status::access_denied);
}

TEST_CASE("windows build number is available") {
    const auto build = windows_build_number();
    CHECK(build >= 7600);
}

TEST_CASE("version string is sane") {
    const auto version = windows_version_string();
    CHECK(version.find('.') != std::string::npos);
}

TEST_CASE("temp path is unique") {
    const auto first = make_temp_path("kdu_test_", ".sys");
    const auto second = make_temp_path("kdu_test_", ".sys");
    CHECK(first != second);
    CHECK(first.find("kdu_test_") != std::string::npos);
    CHECK(first.find(".sys") != std::string::npos);
}

TEST_CASE("kernel driver image path is an unquoted NT path") {
    const auto path =
        kernel_driver_image_path("C:\\Windows\\Temp\\kdu_GIO_1.sys");
    CHECK(path == L"\\??\\C:\\Windows\\Temp\\kdu_GIO_1.sys");
    CHECK(path.find(L'"') == std::wstring::npos);
    const auto already_nt =
        kernel_driver_image_path("\\??\\C:\\Windows\\Temp\\k.sys");
    CHECK(already_nt == L"\\??\\C:\\Windows\\Temp\\k.sys");
}

TEST_CASE("driver staging path avoids spaces") {
    const auto staging = make_staging_path("kdu_test_", ".sys");
    CHECK(staging.find("kdu_test_") != std::string::npos);
    CHECK(staging.find(".sys") != std::string::npos);
    CHECK(staging.find(' ') == std::string::npos);
    CHECK(staging.find("Temp") != std::string::npos);
}

TEST_CASE("file round trip") {
    const auto path = make_temp_path("kdu_file_", ".bin");
    const std::vector<std::uint8_t> data = {1, 2, 3, 4, 5};
    REQUIRE(write_file(path, data.data(), data.size()).has_value());
    CHECK(file_exists(path));
    auto read = read_file(path);
    REQUIRE(read.has_value());
    CHECK(read.value() == data);
    REQUIRE(remove_file(path).has_value());
    CHECK(!file_exists(path));
}

TEST_CASE("localized error text is converted to UTF-8") {
    // GBK-encoded "你好" (CP_ACP on a Chinese Windows install).
    const std::string ansi("\xC4\xE3\xBA\xC3");
    const auto utf8 = ansi_to_utf8(ansi);
    CHECK(!utf8.empty());
    // Valid UTF-8 must round-trip through the wide conversion.
    CHECK(!to_utf16(utf8).empty());
    const auto message = format_win32_error(ERROR_FILE_NOT_FOUND);
    CHECK(!message.empty());
    // Every byte of the result must form valid UTF-8 (no stray 0xC4 lead
    // bytes from the ANSI code page).
    for (std::size_t index = 0; index < message.size();) {
        const auto byte = static_cast<unsigned char>(message[index]);
        std::size_t length = 1;
        if ((byte & 0x80) == 0) {
            length = 1;
        } else if ((byte & 0xE0) == 0xC0) {
            length = 2;
        } else if ((byte & 0xF0) == 0xE0) {
            length = 3;
        } else if ((byte & 0xF8) == 0xF0) {
            length = 4;
        } else {
            FAIL("invalid UTF-8 lead byte");
        }
        CHECK(index + length <= message.size());
        index += length;
    }
}

TEST_CASE("status strings") {
    CHECK(std::string(status_to_string(Status::ok)) == "ok");
    CHECK(std::string(status_to_string(Status::payload_unavailable)) ==
          "payload_unavailable");
}
