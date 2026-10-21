// blook-kdu e2e helper: an ordinary user-mode process whose memory the kernel
// payload tests read and write through CR3. It allocates a page, fills it with
// a known pattern, publishes {pid, address, pattern} as JSON and waits.
#include <windows.h>

#include <cstdio>
#include <cstring>

int main() {
    constexpr SIZE_T kSize = 0x1000;
    auto* buffer = static_cast<unsigned char*>(::VirtualAlloc(
        nullptr, kSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!buffer) {
        std::fprintf(stderr, "VirtualAlloc failed\n");
        return 1;
    }
    const char* pattern = "KDU-E2E-MARKER";
    std::memcpy(buffer, pattern, std::strlen(pattern) + 1);
    for (SIZE_T index = std::strlen(pattern) + 1; index < kSize; ++index) {
        buffer[index] = static_cast<unsigned char>(index & 0xFF);
    }
    std::printf(
        "{\"pid\":%lu,\"address\":\"0x%llx\",\"size\":%zu,"
        "\"pattern\":\"%s\"}\n",
        static_cast<unsigned long>(::GetCurrentProcessId()),
        static_cast<unsigned long long>(
            reinterpret_cast<unsigned long long>(buffer)),
        static_cast<std::size_t>(kSize), pattern);
    std::fflush(stdout);
    ::Sleep(180000);  // stay alive while the e2e runner works
    ::VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}
