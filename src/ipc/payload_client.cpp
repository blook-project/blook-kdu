// blook-kdu: blook-kchannel adapter (user side) and payload kernel access.
//
// This is the single translation unit that talks to blook-kchannel. The rest of
// the SDK sees only IKernelAccess. The payload image is compiled into the
// executable as a byte array by the build (scripts/gen-payload-blob.ps1).
#include "ipc/payload_client.h"

#include <blook/kchannel.h>

#include <cstring>
#include <mutex>

#include "core/log.h"
#include "payload/kdu_ops.h"

#if __has_include("payload_blob.h")
#include "payload_blob.h"
#define KDU_HAVE_PAYLOAD_BLOB 1
#else
#define KDU_HAVE_PAYLOAD_BLOB 0
#endif

namespace blook::kdu::ipc {
namespace {

constexpr uint32_t kCallTimeoutMs = 10000;
constexpr uint32_t kMapTimeoutMs = 10000;
constexpr uint32_t kPayloadRegionSize = 0x40000;  // 64 KiB payloads need it

Status kc_status_to_status(kc_status status) {
    switch (status) {
        case KC_OK:
            return Status::ok;
        case KC_ERR_PARAM:
            return Status::invalid_argument;
        case KC_ERR_NOMEM:
            return Status::no_memory;
        case KC_ERR_STATE:
            return Status::kernel_access_error;
        case KC_ERR_AUTH:
            return Status::auth_failed;
        case KC_ERR_TIMEOUT:
            return Status::timeout;
        case KC_ERR_BUSY:
            return Status::busy;
        case KC_ERR_NOT_FOUND:
            return Status::not_found;
        case KC_ERR_ALREADY:
            return Status::already_exists;
        case KC_ERR_UNSUPPORTED:
            return Status::not_supported;
        case KC_ERR_IO:
            return Status::io_error;
        case KC_ERR_MAP:
            return Status::mapping_failed;
        case KC_ERR_PEER_GONE:
            return Status::driver_not_loaded;
        case KC_ERR_HANDLER:
        case KC_ERR_INTERNAL:
        case KC_ERR_MAGIC:
        case KC_ERR_VERSION:
        default:
            return Status::protocol_error;
    }
}

template <typename Request>
Result<void> call_with_result(kc_client* client, uint16_t opcode,
                              const Request& request, void* output,
                              std::size_t output_size, uint32_t* out_len) {
    uint32_t written = 0;
    const kc_status status = kc_call(
        client, opcode, &request, static_cast<uint32_t>(sizeof(request)),
        output, static_cast<uint32_t>(output_size), &written, kCallTimeoutMs);
    if (status != KC_OK) {
        return Result<void>::fail(kc_status_to_status(status),
                                  kc_status_str(status));
    }
    if (out_len) {
        *out_len = written;
    }
    return Result<void>::ok();
}

Result<void> call_io(kc_client* client, uint16_t opcode, const void* input,
                     std::size_t input_size, void* output,
                     std::size_t output_size, uint32_t* out_len) {
    uint32_t written = 0;
    const kc_status status = kc_call(
        client, opcode, input, static_cast<uint32_t>(input_size), output,
        static_cast<uint32_t>(output_size), &written, kCallTimeoutMs);
    if (status != KC_OK) {
        return Result<void>::fail(kc_status_to_status(status),
                                  kc_status_str(status));
    }
    if (out_len) {
        *out_len = written;
    }
    return Result<void>::ok();
}

// ---------------------------------------------------------------------------
// PayloadKernelAccess: IKernelAccess over kchannel RPC
// ---------------------------------------------------------------------------
class PayloadKernelAccess final : public IKernelAccess {
   public:
    explicit PayloadKernelAccess(kc_client* client) : client_(client) {}

    [[nodiscard]] std::string_view backend_name() const override {
        return "payload";
    }
    [[nodiscard]] exploits::Capability capabilities() const override {
        return exploits::Capability::physical_read |
               exploits::Capability::physical_write |
               exploits::Capability::virtual_read |
               exploits::Capability::virtual_write |
               exploits::Capability::translate;
    }

    Result<std::size_t> read_physical(std::uint64_t address, void* buffer,
                                      std::size_t size) override {
        return transfer(KDU_OP_READ_PHYSICAL, address, buffer, size);
    }
    Result<std::size_t> write_physical(std::uint64_t address,
                                       const void* buffer,
                                       std::size_t size) override {
        return transfer(KDU_OP_WRITE_PHYSICAL, address,
                        const_cast<void*>(buffer), size);
    }
    Result<std::size_t> read_virtual(std::uint64_t address, void* buffer,
                                     std::size_t size) override {
        return transfer(KDU_OP_READ_VIRTUAL, address, buffer, size);
    }
    Result<std::size_t> write_virtual(std::uint64_t address, const void* buffer,
                                      std::size_t size) override {
        return transfer(KDU_OP_WRITE_VIRTUAL, address,
                        const_cast<void*>(buffer), size);
    }

    Result<std::uint64_t> translate(std::uint64_t address) override {
        kdu_translate_request request{};
        request.header.magic = KDU_PAYLOAD_MAGIC;
        request.header.opcode = KDU_OP_TRANSLATE;
        request.header.size = sizeof(request);
        request.address = address;
        kdu_translate_request response{};
        auto result = call_with_result(client_, KDU_OP_TRANSLATE, request,
                                       &response, sizeof(response), nullptr);
        if (!result) {
            return Result<std::uint64_t>::fail(result.error().code,
                                               result.error().message);
        }
        return Result<std::uint64_t>::ok(response.physical);
    }

    Result<std::uint64_t> process_cr3(std::uint32_t pid) override {
        kdu_cr3_request request{};
        request.header.magic = KDU_PAYLOAD_MAGIC;
        request.header.opcode = KDU_OP_PROCESS_CR3;
        request.header.size = sizeof(request);
        request.pid = pid;
        kdu_cr3_request response{};
        auto result = call_with_result(client_, KDU_OP_PROCESS_CR3, request,
                                       &response, sizeof(response), nullptr);
        if (!result) {
            return Result<std::uint64_t>::fail(result.error().code,
                                               result.error().message);
        }
        return Result<std::uint64_t>::ok(response.cr3);
    }

    Result<std::vector<ModuleInfo>> enumerate_modules() override {
        std::vector<ModuleInfo> modules;
        for (std::uint32_t index = 0;; ++index) {
            kdu_module_request request{};
            request.header.magic = KDU_PAYLOAD_MAGIC;
            request.header.opcode = KDU_OP_ENUM_MODULES;
            request.header.size = sizeof(request);
            request.index = index;
            kdu_module_info response{};
            uint32_t written = 0;
            const kc_status status =
                kc_call(client_, KDU_OP_ENUM_MODULES, &request, sizeof(request),
                        &response, sizeof(response), &written, kCallTimeoutMs);
            if (status == KC_ERR_NOT_FOUND) {
                break;
            }
            if (status != KC_OK || written < sizeof(response)) {
                return Result<std::vector<ModuleInfo>>::fail(
                    kc_status_to_status(status), kc_status_str(status));
            }
            ModuleInfo module;
            module.name = response.name;
            module.base = response.base;
            module.size = response.size;
            modules.push_back(std::move(module));
        }
        return Result<std::vector<ModuleInfo>>::ok(std::move(modules));
    }

    Result<std::size_t> read_process(std::uint32_t pid, std::uint64_t address,
                                     void* buffer, std::size_t size) override {
        return process_transfer(KDU_OP_READ_PROCESS, pid, address, buffer,
                                size);
    }
    Result<std::size_t> write_process(std::uint32_t pid, std::uint64_t address,
                                      const void* buffer,
                                      std::size_t size) override {
        return process_transfer(KDU_OP_WRITE_PROCESS, pid, address,
                                const_cast<void*>(buffer), size);
    }

   private:
    // One chunk at a time: kchannel payloads are capped at ~64 KiB and the
    // payload validates the size again.
    static constexpr std::size_t kChunk = KDU_MAX_TRANSFER;

    Result<std::size_t> transfer(uint16_t opcode, std::uint64_t address,
                                 void* buffer, std::size_t size) {
        const bool write =
            opcode == KDU_OP_WRITE_PHYSICAL || opcode == KDU_OP_WRITE_VIRTUAL;
        std::size_t done = 0;
        while (done < size) {
            const auto take = std::min(kChunk, size - done);
            std::vector<std::uint8_t> input(sizeof(kdu_mem_request) +
                                            (write ? take : 0));
            auto* request = reinterpret_cast<kdu_mem_request*>(input.data());
            request->header.magic = KDU_PAYLOAD_MAGIC;
            request->header.opcode = opcode;
            request->header.size = static_cast<uint32_t>(input.size());
            request->address = address + done;
            request->size = static_cast<uint32_t>(take);
            if (write) {
                std::memcpy(input.data() + sizeof(kdu_mem_request),
                            static_cast<std::uint8_t*>(buffer) + done, take);
            }
            if (write) {
                auto result = call_io(client_, opcode, input.data(),
                                      input.size(), nullptr, 0, nullptr);
                if (!result) {
                    return Result<std::size_t>::fail(result.error().code,
                                                     result.error().message);
                }
            } else {
                auto result = call_io(
                    client_, opcode, input.data(), sizeof(kdu_mem_request),
                    static_cast<std::uint8_t*>(buffer) + done, take, nullptr);
                if (!result) {
                    return Result<std::size_t>::fail(result.error().code,
                                                     result.error().message);
                }
            }
            done += take;
        }
        return Result<std::size_t>::ok(done);
    }

    Result<std::size_t> process_transfer(uint16_t opcode, std::uint32_t pid,
                                         std::uint64_t address, void* buffer,
                                         std::size_t size) {
        const bool write = opcode == KDU_OP_WRITE_PROCESS;
        std::size_t done = 0;
        while (done < size) {
            const auto take = std::min(kChunk, size - done);
            std::vector<std::uint8_t> input(sizeof(kdu_process_request) +
                                            (write ? take : 0));
            auto* request =
                reinterpret_cast<kdu_process_request*>(input.data());
            request->header.magic = KDU_PAYLOAD_MAGIC;
            request->header.opcode = opcode;
            request->header.size = static_cast<uint32_t>(input.size());
            request->pid = pid;
            request->address = address + done;
            request->size = static_cast<uint32_t>(take);
            if (write) {
                std::memcpy(input.data() + sizeof(kdu_process_request),
                            static_cast<std::uint8_t*>(buffer) + done, take);
                auto result = call_io(client_, opcode, input.data(),
                                      input.size(), nullptr, 0, nullptr);
                if (!result) {
                    return Result<std::size_t>::fail(result.error().code,
                                                     result.error().message);
                }
            } else {
                auto result = call_io(
                    client_, opcode, input.data(), sizeof(kdu_process_request),
                    static_cast<std::uint8_t*>(buffer) + done, take, nullptr);
                if (!result) {
                    return Result<std::size_t>::fail(result.error().code,
                                                     result.error().message);
                }
            }
            done += take;
        }
        return Result<std::size_t>::ok(done);
    }

    kc_client* client_ = nullptr;
};

// ---------------------------------------------------------------------------
// Payload backend
// ---------------------------------------------------------------------------
class KChannelPayloadBackend final : public IPayloadBackend {
   public:
    KChannelPayloadBackend() = default;
    ~KChannelPayloadBackend() override { (void)unload(); }

    Result<std::unique_ptr<IKernelAccess>> map(IManualMapper& mapper,
                                               const MapOptions& options,
                                               MappedImage* mapping) override;
    Result<void> unload() override;
    [[nodiscard]] bool attached() const override { return client_ != nullptr; }

   private:
    kc_client* client_ = nullptr;
    std::unique_ptr<PayloadKernelAccess> access_;
};

}  // namespace

std::unique_ptr<IPayloadBackend> create_payload_backend() {
    return std::make_unique<KChannelPayloadBackend>();
}

Result<std::unique_ptr<IKernelAccess>> KChannelPayloadBackend::map(
    IManualMapper& mapper, const MapOptions& options, MappedImage* mapping) {
#if !KDU_HAVE_PAYLOAD_BLOB
    (void)mapper;
    (void)options;
    (void)mapping;
    return Result<std::unique_ptr<IKernelAccess>>::fail(
        Status::payload_unavailable,
        "the kernel payload is not embedded in this build (run "
        "scripts/build.ps1 / build the kdu_payload target first)");
#else
    if (client_) {
        return Result<std::unique_ptr<IKernelAccess>>::fail(
            Status::already_exists, "payload already attached");
    }
    kc_attach_opts attach_options{};
    attach_options.region_size = kPayloadRegionSize;
    attach_options.mode = KC_MODE_MAPPED;
    attach_options.cipher = KC_CIPHER_CHACHA20;
    attach_options.peer_pid = 0;  // current process
    attach_options.flags = 0;
    attach_options.debug_tag = "blook-kdu";
    kc_client* client = nullptr;
    kc_status status = kc_attach(&attach_options, &client);
    if (status != KC_OK) {
        return Result<std::unique_ptr<IKernelAccess>>::fail(
            kc_status_to_status(status), kc_status_str(status));
    }
    kc_bootstrap bootstrap{};
    status = kc_get_bootstrap(client, &bootstrap);
    if (status != KC_OK) {
        kc_detach(client);
        return Result<std::unique_ptr<IKernelAccess>>::fail(
            kc_status_to_status(status), kc_status_str(status));
    }

    // The map entry parameter is a kernel copy of kdu_payload_params.
    kdu_payload_params params{};
    params.magic = KDU_PAYLOAD_PARAM_MAGIC;
    params.size = sizeof(params);
    params.image_base = 0;
    params.image_size = kdu_payload_image_size;
    params.windows_build = 0;
    std::memcpy(&params.bootstrap, &bootstrap, sizeof(bootstrap));

    MapOptions map_options = options;
    map_options.name =
        options.name.empty() ? "blook-kdu-payload" : options.name;
    map_options.call_entry = true;
    map_options.bootstrap.assign(
        reinterpret_cast<const std::uint8_t*>(&params),
        reinterpret_cast<const std::uint8_t*>(&params) + sizeof(params));

    auto mapped = mapper.map(std::span<const std::uint8_t>(
                                 kdu_payload_image, kdu_payload_image_size),
                             map_options);
    if (!mapped) {
        kc_detach(client);
        return Result<std::unique_ptr<IKernelAccess>>::fail(
            mapped.error().code, mapped.error().message);
    }
    status = kc_attach_finish(client, kMapTimeoutMs);
    if (status != KC_OK) {
        kc_detach(client);
        return Result<std::unique_ptr<IKernelAccess>>::fail(
            kc_status_to_status(status),
            std::string("kchannel handshake failed: ") + kc_status_str(status));
    }
    client_ = client;
    access_ = std::make_unique<PayloadKernelAccess>(client_);
    if (mapping) {
        *mapping = mapped.value();
        mapping->name = map_options.name;
    }
    KDU_LOG_INFO("payload mapped at 0x{:x} ({} bytes)", mapped->base,
                 mapped->size);
    return Result<std::unique_ptr<IKernelAccess>>::ok(std::move(access_));
#endif  // KDU_HAVE_PAYLOAD_BLOB
}

Result<void> KChannelPayloadBackend::unload() {
    access_.reset();
    if (!client_) {
        return Result<void>::ok();
    }
    // Ask the payload to stop the kchannel server, then detach. The mapped
    // image itself stays allocated: freeing the pool that is executing is not
    // possible without a second stage; this is documented as a known residual.
    kdu_rpc_header request{};
    request.magic = KDU_PAYLOAD_MAGIC;
    request.opcode = KDU_OP_UNLOAD;
    request.size = sizeof(request);
    (void)call_io(client_, KDU_OP_UNLOAD, &request, sizeof(request), nullptr, 0,
                  nullptr);
    kc_detach(client_);
    client_ = nullptr;
    return Result<void>::ok();
}

}  // namespace blook::kdu::ipc
