// blook-kdu: DeviceIoControl wrapper implementing IDeviceIo.
#pragma once

#include <windows.h>

#include <cstdint>
#include <memory>

#include "exploits/common/iexploit.h"

namespace blook::kdu::core {

class DeviceIo final : public exploits::IDeviceIo {
   public:
    explicit DeviceIo(HANDLE device);
    ~DeviceIo() override;

    DeviceIo(const DeviceIo&) = delete;
    DeviceIo& operator=(const DeviceIo&) = delete;

    Result<std::size_t> ioctl(std::uint32_t code, const void* input,
                              std::size_t input_size, void* output,
                              std::size_t output_size) override;

    [[nodiscard]] HANDLE handle() const noexcept { return device_; }

   private:
    HANDLE device_ = nullptr;
};

// Open a device by symbolic link (e.g. "\\\\.\\GIO"). Retries briefly because
// services report RUNNING slightly before the device object is ready.
Result<std::unique_ptr<DeviceIo>> open_device(
    const std::string& device_name,
    DWORD desired_access = GENERIC_READ | GENERIC_WRITE, int retries = 20,
    int delay_ms = 50);

}  // namespace blook::kdu::core
