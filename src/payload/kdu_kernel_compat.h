// blook-kdu: WDK compatibility shims for manually mapped kernel payloads.
//
// The WDK 10.0.26100 install used by this build environment declares
// ExAllocatePoolWithTag but not ExAllocatePool2 (the newer API introduced with
// Windows 10 2004 and used by blook-kchannel's kernel library). A manually
// mapped payload cannot rely on a kernel import for it anyway, so a tiny inline
// shim is enough: allocate with the old API and zero the buffer, which is the
// documented ExAllocatePool2 contract.
//
// This header is force-included (/FI) into every payload translation unit
// before kchannel's own headers.
#pragma once

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

// POOL_FLAG_NON_PAGED is 0x40 in the new pool flag scheme.
static __inline PVOID ExAllocatePool2(ULONG flags, SIZE_T bytes, ULONG tag) {
    const POOL_TYPE pool = (flags & 0x40) ? NonPagedPool : PagedPool;
    PVOID memory = ExAllocatePoolWithTag(pool, bytes, tag);
    if (memory) {
        RtlZeroMemory(memory, bytes);
    }
    return memory;
}

#ifdef __cplusplus
}  // extern "C"
#endif
