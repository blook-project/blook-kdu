// Mock device I/O for exploit unit tests.
#pragma once

#include <cstring>
#include <functional>
#include <vector>

#include "exploits/common/iexploit.h"
#include "exploits/common/kernel_access.h"

namespace blook::kdu::testing {

struct IoctlCall {
    std::uint32_t code = 0;
    std::vector<std::uint8_t> input;
    std::size_t output_size = 0;
    std::size_t output_written = 0;
};

class MockDeviceIo final : public exploits::IDeviceIo {
   public:
    using Handler = std::function<Result<std::size_t>(
        std::uint32_t code, const std::uint8_t* input, std::size_t input_size,
        std::uint8_t* output, std::size_t output_size)>;

    MockDeviceIo() = default;
    explicit MockDeviceIo(Handler handler) : handler_(std::move(handler)) {}

    void set_handler(Handler handler) { handler_ = std::move(handler); }

    Result<std::size_t> ioctl(std::uint32_t code, const void* input,
                              std::size_t input_size, void* output,
                              std::size_t output_size) override {
        IoctlCall call;
        call.code = code;
        call.output_size = output_size;
        if (input && input_size) {
            call.input.assign(
                static_cast<const std::uint8_t*>(input),
                static_cast<const std::uint8_t*>(input) + input_size);
        }
        if (!handler_) {
            return Result<std::size_t>::fail(Status::not_supported,
                                             "no mock handler installed");
        }
        auto result = handler_(code, call.input.data(), call.input.size(),
                               static_cast<std::uint8_t*>(output), output_size);
        call.output_written = result ? result.value() : 0;
        calls_.push_back(std::move(call));
        return result;
    }

    [[nodiscard]] const std::vector<IoctlCall>& calls() const { return calls_; }
    void clear_calls() { calls_.clear(); }

   private:
    Handler handler_;
    std::vector<IoctlCall> calls_;
};

// A mock service host that hands out one pre-built device object.
class MockServiceHost final : public exploits::IServiceHost {
   public:
    explicit MockServiceHost(std::unique_ptr<exploits::IDeviceIo> device)
        : device_(std::move(device)) {}

    Result<std::unique_ptr<exploits::IDeviceIo>> start(
        const exploits::ExploitInfo& info) override {
        (void)info;
        started_ = true;
        if (!device_) {
            return Result<std::unique_ptr<exploits::IDeviceIo>>::fail(
                Status::io_error, "mock device already handed out");
        }
        return Result<std::unique_ptr<exploits::IDeviceIo>>::ok(
            std::move(device_));
    }

    Result<void> stop(const exploits::ExploitInfo& info) override {
        (void)info;
        stopped_ = true;
        return Result<void>::ok();
    }

    [[nodiscard]] bool started() const { return started_; }
    [[nodiscard]] bool stopped() const { return stopped_; }

   private:
    std::unique_ptr<exploits::IDeviceIo> device_;
    bool started_ = false;
    bool stopped_ = false;
};

// A mock kernel access backend (host unit tests for SDK-level logic).
class MockKernelAccess final : public IKernelAccess {
   public:
    [[nodiscard]] std::string_view backend_name() const override {
        return "mock";
    }
    [[nodiscard]] exploits::Capability capabilities() const override {
        return exploits::Capability::physical_read |
               exploits::Capability::physical_write |
               exploits::Capability::virtual_read |
               exploits::Capability::virtual_write;
    }
    Result<std::size_t> read_physical(std::uint64_t address, void* buffer,
                                      std::size_t size) override {
        std::memcpy(buffer, physical.data() + address, size);
        return Result<std::size_t>::ok(size);
    }
    Result<std::size_t> write_physical(std::uint64_t address,
                                       const void* buffer,
                                       std::size_t size) override {
        std::memcpy(physical.data() + address, buffer, size);
        return Result<std::size_t>::ok(size);
    }
    Result<std::size_t> read_virtual(std::uint64_t address, void* buffer,
                                     std::size_t size) override {
        std::memcpy(buffer, virtual_memory.data() + address, size);
        return Result<std::size_t>::ok(size);
    }
    Result<std::size_t> write_virtual(std::uint64_t address, const void* buffer,
                                      std::size_t size) override {
        std::memcpy(virtual_memory.data() + address, buffer, size);
        return Result<std::size_t>::ok(size);
    }
    Result<std::uint64_t> translate(std::uint64_t address) override {
        return Result<std::uint64_t>::ok(address);
    }

    std::vector<std::uint8_t> physical = std::vector<std::uint8_t>(0x100000);
    std::vector<std::uint8_t> virtual_memory =
        std::vector<std::uint8_t>(0x100000);
};

}  // namespace blook::kdu::testing
