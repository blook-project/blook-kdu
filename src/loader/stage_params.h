// blook-kdu: stage parameters shared by the user-mode mapper and the kernel
// stage image (the stage is a tiny WDK driver image mapped into a victim
// driver's executable pages). Keep this header free of C++/STL so both sides
// can include it.
#pragma once

#if defined(_KERNEL_MODE)
typedef unsigned __int8 kdu_u8;
typedef unsigned __int16 kdu_u16;
typedef unsigned __int32 kdu_u32;
typedef unsigned __int64 kdu_u64;
#else
#include <cstdint>
typedef std::uint8_t kdu_u8;
typedef std::uint16_t kdu_u16;
typedef std::uint32_t kdu_u32;
typedef std::uint64_t kdu_u64;
#endif

#define KDU_STAGE_PARAMS_MAGIC 0x504B4453u /* 'SDKP' */
#define KDU_STAGE_RESULT_MAGIC 0x5253444Bu /* 'KDSR' */
#define KDU_STAGE_PARAMS_VERSION 2u

#pragma pack(push, 8)

// Written by the mapper into the stage image's .kparam section before the stage
// is copied into the victim driver and executed. All pointer fields are kernel
// virtual addresses except *_user fields, which are validated by the stage
// running in the loader thread context.
typedef struct kdu_stage_params {
    kdu_u32 magic;
    kdu_u32 version;
    kdu_u32 pool_tag;
    kdu_u32 reserved0;

    kdu_u64 original_dispatch;  // VA of the unpatched dispatch entry
    kdu_u64 dispatch_va;        // VA of the patched dispatch entry
    kdu_u8 dispatch_backup[8];  // original first 5 bytes of the dispatch entry

    kdu_u64 stage_va;    // VA the stage image was copied to
    kdu_u64 stage_size;  // bytes occupied by the stage image

    kdu_u64 image_source_user;  // prepared image bytes in the loader process
    kdu_u64 image_size;
    kdu_u64 image_alloc_size;  // pool bytes requested (image + bootstrap page)
    kdu_u64 reloc_offsets_user;  // user VA of the u32 relocation offset array
    kdu_u64 reloc_count;
    kdu_u64 preferred_base;
    kdu_u64 entry_offset;

    kdu_u64 bootstrap_source_user;  // map entry parameter bytes
    kdu_u64 bootstrap_size;

    kdu_u64 allocate_pool;  // ExAllocatePoolWithTag kernel VA
    kdu_u64 result_user;    // user VA of kdu_stage_result
} kdu_stage_params;

typedef struct kdu_stage_result {
    kdu_u32 magic;
    kdu_u32 status;  // NTSTATUS of the mapped image entry point
    kdu_u64 image_base;
} kdu_stage_result;

#pragma pack(pop)
