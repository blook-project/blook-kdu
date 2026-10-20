/* blook-kdu payload RPC protocol (shared user / kernel).
 *
 * Every request is a plain struct with fixed-size scalar fields; variable
 * payloads follow the struct in the same kchannel message. All values are
 * little endian x64, which is the only supported platform.
 *
 * Opcodes live above KC_OP_APP_MIN (0x8000) so kchannel delivers them
 * verbatim. Handlers always validate every field: a malformed request returns
 * an error and never faults the kernel.
 */
#ifndef BLOOK_KDU_OPS_H
#define BLOOK_KDU_OPS_H

#include <blook/kchannel.h>

#define KDU_PAYLOAD_MAGIC 0x55444B42u       /* 'BKDU' */
#define KDU_PAYLOAD_PARAM_MAGIC 0x50444B42u /* 'BKDP' */

#define KDU_OP_PING 0x8000u
#define KDU_OP_QUERY 0x8001u
#define KDU_OP_READ_PHYSICAL 0x8010u
#define KDU_OP_WRITE_PHYSICAL 0x8011u
#define KDU_OP_READ_VIRTUAL 0x8012u
#define KDU_OP_WRITE_VIRTUAL 0x8013u
#define KDU_OP_TRANSLATE 0x8014u
#define KDU_OP_READ_PROCESS 0x8020u
#define KDU_OP_WRITE_PROCESS 0x8021u
#define KDU_OP_PROCESS_CR3 0x8022u
#define KDU_OP_DSE_STATUS 0x8030u
#define KDU_OP_DSE_SET 0x8031u
#define KDU_OP_ENUM_MODULES 0x8040u
#define KDU_OP_UNLOAD 0x8050u

#define KDU_MAX_TRANSFER (64u * 1024u - 64u - 32u)
#define KDU_MAX_MODULE_NAME 96u

#pragma pack(push, 8)

typedef struct kdu_rpc_header {
    uint32_t magic; /* KDU_PAYLOAD_MAGIC, always first */
    uint32_t opcode;
    uint32_t size;   /* bytes of the whole request / response */
    uint32_t status; /* response: 0 = ok, otherwise kdu_status */
} kdu_rpc_header;

/* KDU_OP_QUERY response. */
typedef struct kdu_query_info {
    kdu_rpc_header header;
    uint32_t abi_major;
    uint32_t abi_minor;
    uint32_t windows_build;
    uint32_t flags;
    uint64_t payload_base;
    uint64_t payload_size;
} kdu_query_info;

/* KDU_OP_READ_* / WRITE_* request. Data follows for writes. */
typedef struct kdu_mem_request {
    kdu_rpc_header header;
    uint64_t address;
    uint32_t size;
    uint32_t reserved;
} kdu_mem_request;

/* KDU_OP_TRANSLATE request / response. */
typedef struct kdu_translate_request {
    kdu_rpc_header header;
    uint64_t address;
    uint64_t physical;
} kdu_translate_request;

/* KDU_OP_*_PROCESS request. Data follows for writes. */
typedef struct kdu_process_request {
    kdu_rpc_header header;
    uint32_t pid;
    uint32_t size;
    uint64_t address;
} kdu_process_request;

/* KDU_OP_PROCESS_CR3 request / response. */
typedef struct kdu_cr3_request {
    kdu_rpc_header header;
    uint32_t pid;
    uint32_t reserved;
    uint64_t cr3;
    uint64_t peb;
} kdu_cr3_request;

/* KDU_OP_DSE_STATUS response and KDU_OP_DSE_SET request. */
typedef struct kdu_dse_request {
    kdu_rpc_header header;
    uint32_t options;  /* current / requested g_CiOptions value */
    uint32_t original; /* response: value before the patch */
    uint64_t address;  /* g_CiOptions kernel VA */
} kdu_dse_request;

/* KDU_OP_ENUM_MODULES request and response. */
typedef struct kdu_module_request {
    kdu_rpc_header header;
    uint32_t index;
    uint32_t flags;
} kdu_module_request;

typedef struct kdu_module_info {
    kdu_rpc_header header;
    uint64_t base;
    uint32_t size;
    uint32_t flags;
    char name[KDU_MAX_MODULE_NAME];
} kdu_module_info;

#pragma pack(pop)

/* Map entry parameter, written by the manual mapper into kernel memory. */
#pragma pack(push, 8)
typedef struct kdu_payload_params {
    uint32_t magic; /* KDU_PAYLOAD_PARAM_MAGIC */
    uint32_t size;  /* sizeof(kdu_payload_params) */
    uint64_t image_base;
    uint64_t image_size;
    uint32_t windows_build;
    uint32_t reserved;
    kc_bootstrap bootstrap; /* kchannel bootstrap, filled by the loader */
} kdu_payload_params;
#pragma pack(pop)

#endif /* BLOOK_KDU_OPS_H */
