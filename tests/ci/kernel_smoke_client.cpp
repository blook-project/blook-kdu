// blook-kdu: minimal CI client for the kernel-load smoke driver.
//
// Opens \\.\KduCiSmoke, performs two buffered IOCTLs (magic DWORD and a kernel
// code pointer) and prints a machine-readable result. The kernel pointer proves
// a functional kernel-loaded data path (the bytes came from a running driver).
#include <windows.h>
#include <winioctl.h>

#include <cstdio>

namespace {

constexpr DWORD kDeviceType = 0x8333;
constexpr DWORD kMagicIoctl =
    CTL_CODE(kDeviceType, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD kInfoIoctl =
    CTL_CODE(kDeviceType, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD kExpectedMagic = 0x5355444B;  // "KDUS"

}  // namespace

int main() {
    HANDLE device =
        ::CreateFileW(L"\\\\.\\KduCiSmoke", GENERIC_READ | GENERIC_WRITE, 0,
                      nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        std::printf("{\"ok\":false,\"error\":\"open\",\"win32\":%lu}\n",
                    ::GetLastError());
        return 1;
    }
    DWORD magic = 0;
    DWORD returned = 0;
    const BOOL magic_ok =
        ::DeviceIoControl(device, kMagicIoctl, nullptr, 0, &magic,
                          sizeof(magic), &returned, nullptr);
    ULONGLONG kernel_pointer = 0;
    DWORD info_returned = 0;
    const BOOL info_ok =
        ::DeviceIoControl(device, kInfoIoctl, nullptr, 0, &kernel_pointer,
                          sizeof(kernel_pointer), &info_returned, nullptr);
    const DWORD error = ::GetLastError();
    ::CloseHandle(device);

    const bool canonical_kernel = kernel_pointer >= 0xFFFF800000000000ull;
    const bool ok = magic_ok && returned == sizeof(magic) &&
                    magic == kExpectedMagic && info_ok &&
                    info_returned == sizeof(kernel_pointer) && canonical_kernel;
    std::printf(
        "{\"ok\":%s,\"magic\":%lu,\"kernel_pointer\":\"0x%llx\","
        "\"canonical\":%s,\"win32\":%lu}\n",
        ok ? "true" : "false", magic,
        static_cast<unsigned long long>(kernel_pointer),
        canonical_kernel ? "true" : "false", error);
    return ok ? 0 : 1;
}
