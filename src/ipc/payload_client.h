// blook-kdu: payload backend (blook-kchannel client side).
//
// The payload is a small kernel driver that is manual-mapped through a
// vulnerable driver and talks to the SDK over blook-kchannel. This header is
// the only place that knows about kchannel on the user-mode side: the rest of
// the SDK sees IKernelAccess.
#pragma once

#include <memory>

#include "blook/kdu/kdu.h"
#include "blook/kdu/types.h"
#include "exploits/common/kernel_access.h"
#include "loader/manual_map.h"

namespace blook::kdu::ipc {

// Owns one kchannel session and the mapped payload image.
class IPayloadBackend {
   public:
    virtual ~IPayloadBackend() = default;

    // Map the embedded payload and attach to it. On success returns the
    // payload-backed kernel access object and fills `mapping`.
    // `mapper` may be null for a service-only load (no vulnerable driver).
    virtual Result<std::unique_ptr<IKernelAccess>> map(
        IManualMapper* mapper, const MapOptions& options,
        MappedImage* mapping) = 0;

    // DSE control forwarded to the payload driver (service or mapped).
    virtual Result<DseState> dse_state() {
        return Result<DseState>::fail(Status::not_supported);
    }
    virtual Result<void> dse_disable() {
        return Result<void>::fail(Status::not_supported);
    }
    virtual Result<void> dse_restore() {
        return Result<void>::fail(Status::not_supported);
    }

    // Unload the payload (kchannel detach -> payload exit -> pool freed).
    virtual Result<void> unload() = 0;

    [[nodiscard]] virtual bool attached() const = 0;
};

// Returns nullptr when this build has no kchannel support (built without
// --kchannel_dir), so the SDK can fall back to the driver-only backend.
std::unique_ptr<IPayloadBackend> create_payload_backend();

}  // namespace blook::kdu::ipc
