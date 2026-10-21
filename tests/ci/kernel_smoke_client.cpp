// blook-kdu: minimal CI client for the kernel-load smoke driver.
//
// Opens \\.\KduCiSmoke, performs one buffered IOCTL and asserts the magic
// DWORD, then prints a machine-readable result. Used by the GitHub Actions
// `kernel-load-smoke` job after it signed and started kernel_smoke_driver.
#include <windows.h>
#include <winioctl.h>

#include <cstdio>

namespace {

constexpr DWORD kDeviceType = 0x8333;
constexpr DWORD kIoctlMagic =
    CTL_CODE(kDeviceType, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
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
    DWORD value = 0;
    DWORD returned = 0;
    const BOOL sent = ::DeviceIoControl(device, kIoctlMagic, nullptr, 0, &value,
                                        sizeof(value), &returned, nullptr);
    const DWORD error = ::GetLastError();
    ::CloseHandle(device);
    if (!sent || returned != sizeof(value) || value != kExpectedMagic) {
        std::printf(
            "{\"ok\":false,\"error\":\"ioctl\",\"win32\":%lu,"
            "\"returned\":%lu,\"value\":%lu}\n",
            error, returned, value);
        return 1;
    }
    std::printf("{\"ok\":true,\"magic\":%lu}\n", value);
    return 0;
}
