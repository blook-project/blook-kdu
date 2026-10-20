// blook-kdu: embedded resource loader.
#include "core/resources.h"

#include <windows.h>

#include "core/log.h"
#include "core/win32.h"

namespace blook::kdu::core {

Result<std::span<const std::uint8_t>> load_embedded_resource(
    std::uint32_t resource_id) {
    const HMODULE module = ::GetModuleHandleW(nullptr);
    const HRSRC resource =
        ::FindResourceW(module, MAKEINTRESOURCEW(resource_id),
                        reinterpret_cast<LPCWSTR>(RT_RCDATA));
    if (!resource) {
        return Result<std::span<const std::uint8_t>>::fail(
            Status::not_found,
            "RCDATA resource " + std::to_string(resource_id) + " missing");
    }
    const HGLOBAL loaded = ::LoadResource(module, resource);
    if (!loaded) {
        const DWORD error = ::GetLastError();
        return Result<std::span<const std::uint8_t>>::fail(
            win32_status(error),
            "LoadResource failed: " + format_win32_error(error));
    }
    const auto* data = static_cast<const std::uint8_t*>(::LockResource(loaded));
    const DWORD size = ::SizeofResource(module, resource);
    if (!data || size == 0) {
        return Result<std::span<const std::uint8_t>>::fail(
            Status::invalid_image, "empty RCDATA resource");
    }
    KDU_LOG_TRACE("loaded embedded resource {} ({} bytes)", resource_id, size);
    return Result<std::span<const std::uint8_t>>::ok(
        std::span<const std::uint8_t>(data, size));
}

bool has_embedded_resource(std::uint32_t resource_id) {
    const HMODULE module = ::GetModuleHandleW(nullptr);
    return ::FindResourceW(module, MAKEINTRESOURCEW(resource_id),
                           reinterpret_cast<LPCWSTR>(RT_RCDATA)) != nullptr;
}

}  // namespace blook::kdu::core
