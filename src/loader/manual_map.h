// blook-kdu: manual mapper.
//
// Maps an arbitrary x64 kernel image (.sys) into kernel memory without going
// through the service manager and without leaving a driver object behind:
//
//   1. the image is prepared in user mode: headers + sections are laid out at
//      their virtual addresses, imports are resolved against the loaded
//      ntoskrnl export table, and the DIR64 relocation offsets are collected;
//   2. a small position-independent stage-1 stub is placed into a spare page of
//      an already loaded (victim) driver; its dispatch routine is redirected to
//      the stub and an IOCTL triggers it. The stub runs in kernel context,
//      allocates pool memory, copies the prepared image, applies relocations,
//      invokes the image entry point with the caller-supplied bootstrap block,
//      restores the patched pages and resumes the original dispatch;
//   3. the pool allocation is intentionally never freed: it becomes the mapped
//      driver. The payload (kchannel server) frees it on unload.
#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "blook/kdu/kdu.h"
#include "blook/kdu/types.h"
#include "exploits/common/iexploit.h"
#include "exploits/common/kernel_access.h"

namespace blook::kdu {

// A prepared kernel image, ready to be copied into kernel memory.
struct PreparedImage {
    std::vector<std::uint8_t> mapped;  // SizeOfImage bytes, sections in place
    std::vector<std::uint32_t> relocations;  // offsets of DIR64 slots in mapped
    std::uint32_t size_of_image = 0;
    std::uint32_t entry_offset = 0;
    std::uint64_t preferred_base = 0;
    std::string dll_name;
    std::vector<std::string> imported_modules;

    // /GS security cookie slots (0 when the image does not use one). A manually
    // mapped image keeps the linker default cookie unless we randomize it; the
    // cookie lives in a RIP-relative data slot, so patching the data bytes is
    // enough and survives relocation.
    std::uint32_t security_cookie_offset = 0;
    std::uint32_t security_cookie_complement_offset = 0;

    // True when the image carries an exception directory. Such images need
    // their unwind tables registered with the kernel to use SEH; the mapper
    // cannot do that for an arbitrary image, which is documented.
    bool has_exception_directory = false;
};

// Replace the /GS security cookie and its complement with `cookie` (no-op when
// the image has none). `cookie` must not be zero.
void initialize_security_cookie(PreparedImage& image, std::uint64_t cookie);

// Prepare an image for mapping: parse/validate, lift sections, resolve imports
// and collect relocations. Pure user-mode code, unit-tested with synthetic
// images.
Result<PreparedImage> prepare_image(std::span<const std::uint8_t> image);

class IManualMapper {
   public:
    virtual ~IManualMapper() = default;

    // Map an image and optionally invoke its entry point.
    virtual Result<MappedImage> map(std::span<const std::uint8_t> image,
                                    const MapOptions& options) = 0;

    // Best-effort unmap of a previously mapped image.
    virtual Result<void> unmap(std::uint64_t base) = 0;
};

// Real mapper: uses the kernel access backend for reads/writes and the service
// host to load the victim driver whose dispatch routine is patched.
class ManualMapper final : public IManualMapper {
   public:
    ManualMapper(IKernelAccess& access, exploits::IServiceHost& services);
    ~ManualMapper() override;

    ManualMapper(const ManualMapper&) = delete;
    ManualMapper& operator=(const ManualMapper&) = delete;

    Result<MappedImage> map(std::span<const std::uint8_t> image,
                            const MapOptions& options) override;
    Result<void> unmap(std::uint64_t base) override;

   private:
    IKernelAccess& access_;
    exploits::IServiceHost& services_;
    std::vector<MappedImage> mapped_;
};

}  // namespace blook::kdu
