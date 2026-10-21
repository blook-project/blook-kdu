// Exploit registry invariant tests.
#include <iostream>
#include <doctest/doctest.h>

#include <set>
#include <string>

#include "exploits/common/iexploit.h"

using namespace blook::kdu;
using namespace blook::kdu::exploits;

TEST_CASE("registry has at least one exploit") {
    CHECK(!all_exploits().empty());
}

TEST_CASE("registry ids are unique and non-empty") {
    std::set<std::string> ids;
    for (const auto& descriptor : all_exploits()) {
        const auto& info = descriptor.info();
        REQUIRE(!info.id.empty());
        CHECK(ids.insert(std::string(info.id)).second);
        CHECK(descriptor.id == info.id);
        CHECK(descriptor.create != nullptr);
        CHECK(descriptor.info != nullptr);
    }
}

TEST_CASE("every exploit has complete metadata") {
    for (const auto& descriptor : all_exploits()) {
        const auto& info = descriptor.info();
        INFO("exploit: " << info.id);
        CHECK(!info.display_name.empty());
        CHECK(!info.description.empty());
        CHECK(!info.driver_file.empty());
        CHECK(!info.service_name.empty());
        CHECK(!info.device_name.empty());
        CHECK(info.image_resource_id != 0);
        CHECK(static_cast<std::uint64_t>(info.capabilities) != 0);
        CHECK(info.min_build <= info.max_build);
        // Exploits must provide at least one memory primitive.
        const bool memory_primitive =
            has_capability(info.capabilities, Capability::physical_read) ||
            has_capability(info.capabilities, Capability::physical_write) ||
            has_capability(info.capabilities, Capability::virtual_read) ||
            has_capability(info.capabilities, Capability::virtual_write);
        CHECK(memory_primitive);
    }
}

TEST_CASE("find_exploit resolves every registered id") {
    for (const auto& descriptor : all_exploits()) {
        const auto* found = find_exploit(descriptor.id);
        REQUIRE(found != nullptr);
        CHECK(found->id == descriptor.id);
    }
    CHECK(find_exploit("definitely-not-an-exploit") == nullptr);
}

TEST_CASE("capability names are stable") {
    const auto names =
        capability_names(Capability::physical_read | Capability::virtual_write);
    REQUIRE(names.size() == 2);
    CHECK(names[0] == "physical_read");
    CHECK(names[1] == "virtual_write");
    CHECK(capability_names(Capability::none).empty());
}
