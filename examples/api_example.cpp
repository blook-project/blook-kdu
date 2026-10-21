// blook-kdu: 20-line public SDK example.
//
// Build: xmake build kdu_api_example (the binary lands next to kdu.exe).
// Run inside a bvmenv VMware guest: kernel execution is refused on hosts.
#include <windows.h>

#include <cstdio>
#include <cstring>

#include <blook/kdu/kdu.h>

int main() {
    auto opened = blook::kdu::kdu_open();
    if (!opened) {
        std::fprintf(stderr, "kdu_open failed: %s\n",
                     opened.error().message.c_str());
        return 1;
    }
    auto& session = opened.value();

    // Map the embedded kernel payload (falls back to the driver backend when
    // unavailable) and read this process's own memory through CR3.
    auto mapped = session.map_payload();
    const auto self = GetCurrentProcessId();
    std::uint8_t buffer[16] = {};
    auto read = session.read_process(self, reinterpret_cast<std::uint64_t>(buffer),
                                     buffer, sizeof(buffer));
    if (!read) {
        std::fprintf(stderr, "read_process failed: %s\n",
                     read.error().message.c_str());
        return 1;
    }
    std::printf("payload@0x%llx backend=%s read=%zu bytes\n",
                static_cast<unsigned long long>(mapped ? mapped->base : 0),
                session.info().backend.c_str(), read.value());
    return 0;
}

