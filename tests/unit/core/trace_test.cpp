// Trace bookkeeping and kernel export parsing tests (no kernel access).
#include <iostream>
#include <doctest/doctest.h>

#include <windows.h>

#include <string>
#include <vector>

#include "core/kernel_exports.h"
#include "core/trace.h"
#include "core/win32.h"

using namespace blook::kdu;
using namespace blook::kdu::core;

TEST_CASE("staged driver bookkeeping round-trips") {
    const std::string service = "kdu-unit-test-service";
    const std::string path = make_temp_path("kdu_unit_", ".sys");
    forget_staged_driver(service);
    remember_staged_driver(service, path);
    {
        auto remembered = remembered_drivers();
        bool found = false;
        for (const auto& driver : remembered) {
            if (driver.service == service) {
                found = true;
                CHECK(driver.path == path);
            }
        }
        CHECK(found);
    }
    forget_staged_driver(service);
    for (const auto& driver : remembered_drivers()) {
        CHECK(driver.service != service);
    }
}

TEST_CASE("scan_traces reports no findings for missing artifacts") {
    const std::string service = "kdu-unit-test-service";
    forget_staged_driver(service);
    auto report =
        scan_traces({service}, {make_temp_path("kdu_unit_missing_", ".sys")});
    REQUIRE(report.has_value());
    CHECK(report->findings.empty());
    CHECK(report->clean());
}

TEST_CASE("kernel exports resolve from the on-disk ntoskrnl") {
    const auto path = system_root() + "\\System32\\ntoskrnl.exe";
    auto exports = load_kernel_exports(path);
    REQUIRE(exports.has_value());
    const auto& map = exports.value();
    CHECK(map.size() > 1000);
    CHECK(map.find("MmCopyMemory") != map.end());
    CHECK(map.find("ExAllocatePoolWithTag") != map.end());
    CHECK(map.find("PsLookupProcessByProcessId") != map.end());
    CHECK(map.find("PsLoadedModuleList") != map.end());
    CHECK(map.find("ThisExportDoesNotExistForSure") == map.end());
}

TEST_CASE("load_kernel_exports fails cleanly for a bad path") {
    auto exports = load_kernel_exports("Z:\\does-not-exist\\ntoskrnl.exe");
    CHECK(!exports.has_value());
    CHECK(exports.error().code != Status::ok);
}
