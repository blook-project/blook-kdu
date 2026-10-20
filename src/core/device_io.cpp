// blook-kdu: DeviceIoControl wrapper implementation.
#include "core/device_io.h"

#include "core/log.h"
#include "core/win32.h"

namespace blook::kdu::core {

DeviceIo::DeviceIo(HANDLE device) : device_(device) {}

DeviceIo::~DeviceIo() {
    if (device_) {
        ::CloseHandle(device_);
        device_ = nullptr;
    }
}

Result<std::size_t> DeviceIo::ioctl(std::uint32_t code, const void* input,
                                    std::size_t input_size, void* output,
                                    std::size_t output_size) {
    if (device_ == nullptr || device_ == INVALID_HANDLE_VALUE) {
        return Result<std::size_t>::fail(Status::driver_not_loaded,
                                         "device handle is closed");
    }
    DWORD bytes_returned = 0;
    const BOOL ok = ::DeviceIoControl(
        device_, code, const_cast<void*>(input), static_cast<DWORD>(input_size),
        output, static_cast<DWORD>(output_size), &bytes_returned, nullptr);
    if (!ok) {
        const DWORD error = ::GetLastError();
        KDU_LOG_TRACE("DeviceIoControl(0x{:x}) failed: {}", code,
                      format_win32_error(error));
        return Result<std::size_t>::fail(
            win32_status(error), "DeviceIoControl(0x" + std::to_string(code) +
                                     ") failed: " + format_win32_error(error));
    }
    return Result<std::size_t>::ok(static_cast<std::size_t>(bytes_returned));
}

Result<std::unique_ptr<DeviceIo>> open_device(const std::string& device_name,
                                              DWORD desired_access, int retries,
                                              int delay_ms) {
    const std::wstring path = to_utf16(device_name);
    for (int attempt = 0; attempt < retries; ++attempt) {
        HANDLE handle = ::CreateFileW(path.c_str(), desired_access,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      nullptr, OPEN_EXISTING, 0, nullptr);
        if (handle != INVALID_HANDLE_VALUE) {
            return Result<std::unique_ptr<DeviceIo>>::ok(
                std::make_unique<DeviceIo>(handle));
        }
        const DWORD error = ::GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
            return Result<std::unique_ptr<DeviceIo>>::fail(
                win32_status(error),
                "CreateFile(" + device_name +
                    ") failed: " + format_win32_error(error));
        }
        ::Sleep(static_cast<DWORD>(delay_ms));
    }
    return Result<std::unique_ptr<DeviceIo>>::fail(
        Status::not_found, "device " + device_name + " did not appear");
}

}  // namespace blook::kdu::core
