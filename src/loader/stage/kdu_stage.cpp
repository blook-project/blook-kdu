// blook-kdu: kernel stage image.
//
// Built as a tiny WDK driver but never loaded by the service manager: the
// manual mapper copies this image into spare executable pages of a victim
// driver, redirects the victim's dispatch routine to kdu_stage_entry and
// triggers it with a device open. The stage runs in kernel context, allocates
// pool memory for the target image, relocates and copies it, invokes the image
// entry point, restores the patched dispatch bytes and finally calls the
// original dispatch routine so the IRP completes normally.
//
// The image is mapped by the same prepare_image() code that handles the target
// image (imports patched, relocations applied to the actual load address), so
// the only thing the stage itself has to do is the runtime work: allocate,
// copy, relocate and call.
#include <ntifs.h>

#include <intrin.h>

#include "loader/stage_params.h"

// Present in the import table; the mapper resolves it to ntoskrnl.
extern "C" {
NTKERNELAPI PVOID NTAPI ExAllocatePoolWithTag(POOL_TYPE pool_type,
                                              SIZE_T number_of_bytes,
                                              ULONG tag);
}

// Parameters are placed in their own section so the mapper can find them by
// name in the PE section table and fill them in before mapping. Compact stage
// builds merge the section into .text, so the block also carries a pre-filled
// magic/version pair that the loader can scan for.
#pragma section(".kparam", read, write)
__declspec(allocate(".kparam")) kdu_stage_params g_kdu_stage_params = {
    KDU_STAGE_PARAMS_MAGIC, KDU_STAGE_PARAMS_VERSION};
#pragma section()

namespace {

// Hand-rolled copy to keep the image free of CRT/memcpy imports and compiler
// helpers; the region is copied in small volatile steps so the compiler cannot
// turn the loop back into a memcpy call.
void copy_bytes(void* destination, const void* source,
                unsigned long long size) {
    auto* out = static_cast<volatile unsigned char*>(destination);
    const auto* in = static_cast<const volatile unsigned char*>(source);
    for (unsigned long long index = 0; index < size; ++index) {
        out[index] = in[index];
    }
}

bool valid_kernel_pointer(unsigned long long value) {
    return value >= 0xFFFF800000000000ull;
}

bool valid_user_pointer(unsigned long long value) {
    return value >= 0x10000ull && value < 0x00007FFFFFFF0000ull;
}

}  // namespace

extern "C" NTSTATUS kdu_stage_entry(void* device_object, void* irp);
extern "C" NTSTATUS kdu_stage_entry(void* device_object, void* irp) {
    auto* params = &g_kdu_stage_params;
    auto* result = reinterpret_cast<kdu_stage_result*>(
        static_cast<unsigned long long>(params->result_user));

    // 1. Restore the patched dispatch entry first: from now on the victim
    // driver
    //    is intact again, so even a failure below leaves the system usable.
    if (valid_kernel_pointer(params->dispatch_va)) {
        copy_bytes(reinterpret_cast<void*>(params->dispatch_va),
                   params->dispatch_backup, 5);
    }

    auto finish = [&](NTSTATUS status) {
        if (result && valid_user_pointer(params->result_user)) {
            result->magic = KDU_STAGE_RESULT_MAGIC;
            result->status = static_cast<kdu_u32>(status);
        }
        // 6. Hand the IRP back to the real dispatch routine.
        using dispatch_fn = NTSTATUS (*)(void*, void*);
        const auto original = reinterpret_cast<dispatch_fn>(
            static_cast<unsigned long long>(params->original_dispatch));
        return original(device_object, irp);
    };

    if (params->magic != KDU_STAGE_PARAMS_MAGIC ||
        params->version != KDU_STAGE_PARAMS_VERSION) {
        return finish(static_cast<NTSTATUS>(0xC000000D));  // INVALID_PARAMETER
    }
    if (!valid_user_pointer(params->image_source_user) ||
        !valid_user_pointer(params->reloc_offsets_user) ||
        params->image_size == 0 || params->bootstrap_size > 0x1000) {
        return finish(static_cast<NTSTATUS>(0xC000000D));
    }

    // 2. Allocate the final image memory. The allocation is page aligned before
    //    use so relocations and the kchannel bootstrap page have a stable base.
    using allocate_fn = PVOID(NTAPI*)(POOL_TYPE, SIZE_T, ULONG);
    const auto allocate = reinterpret_cast<allocate_fn>(params->allocate_pool);
    if (!allocate) {
        return finish(static_cast<NTSTATUS>(0xC000000D));
    }
    // Executable kernel memory: allocated pool is non-executable on current
    // Windows builds, so map pages through an MDL without MdlMappingNoExecute.
    PHYSICAL_ADDRESS highest{};
    highest.QuadPart = -1;
    PHYSICAL_ADDRESS lowest{};
    PMDL mdl = MmAllocatePagesForMdlEx(lowest, highest, lowest,
                                       params->image_alloc_size, MmCached, 0);
    if (!mdl) {
        return finish(static_cast<NTSTATUS>(0xC0000017));  // NO_MEMORY
    }
    void* mapped = MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmCached, nullptr, FALSE, NormalPagePriority);
    if (!mapped) {
        MmFreePagesFromMdl(mdl);
        IoFreeMdl(mdl);
        return finish(static_cast<NTSTATUS>(0xC0000017));
    }
    const auto base =
        (reinterpret_cast<unsigned long long>(mapped) + 0xFFFull) & ~0xFFFull;
    (void)allocate;

    // 3. Copy and relocate the prepared image.
    copy_bytes(reinterpret_cast<void*>(base),
               reinterpret_cast<void*>(params->image_source_user),
               params->image_size);
    const auto delta = base - params->preferred_base;
    auto* relocations =
        reinterpret_cast<const kdu_u32*>(params->reloc_offsets_user);
    for (kdu_u64 index = 0; index < params->reloc_count; ++index) {
        const auto offset = relocations[index];
        if (offset + sizeof(kdu_u64) > params->image_size) {
            continue;
        }
        auto* slot = reinterpret_cast<kdu_u64*>(base + offset);
        *slot += delta;
    }

    // 4. Copy the optional map entry parameter block right after the image.
    if (params->bootstrap_size) {
        copy_bytes(reinterpret_cast<void*>(base + params->image_size),
                   reinterpret_cast<void*>(params->bootstrap_source_user),
                   params->bootstrap_size);
    }

    // 5. Run the image entry point (DriverEntry-style, one parameter).
    using entry_fn = NTSTATUS (*)(void*);
    const auto entry = reinterpret_cast<entry_fn>(base + params->entry_offset);
    const NTSTATUS status =
        entry(params->bootstrap_size
                  ? reinterpret_cast<void*>(base + params->image_size)
                  : nullptr);
    if (result) {
        result->image_base = base;
    }
    return finish(status);
}
