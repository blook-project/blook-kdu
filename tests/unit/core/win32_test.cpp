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

TEST_CASE("status strings") {
    CHECK(std::string(status_to_string(Status::ok)) == "ok");
    CHECK(std::string(status_to_string(Status::payload_unavailable)) ==
          "payload_unavailable");
}
