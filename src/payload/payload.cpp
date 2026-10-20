// blook-kdu kernel payload.
//
// Mapped into kernel memory by the manual mapper. The map entry receives a
// KDU_PAYLOAD_PARAM struct (kernel copy, written by the mapper) that carries
// the blook-kchannel bootstrap block. The payload starts the kchannel server
// and serves the KDU_OP_* RPC protocol: physical / kernel-virtual / process
// (CR3) memory, g_CiOptions control, module enumeration and graceful unload.
//
// Constraints (manual mapping):
//   * no DriverObject, no device object, no registry, no CRT, no exceptions,
//     no RTTI, no static initialisers with side effects;
//   * entry runs at PASSIVE_LEVEL in the loader thread context, which is what
//     kchannel needs to lock the shared user pages;
//   * every request is validated; malformed input returns an error and never
//     faults or blue-screens the machine.
#include <ntifs.h>

#include <blook/kchannel_km.h>

#include <intrin.h>
#include <ntimage.h>

#include "payload/kdu_ops.h"

extern "C" {
NTKERNELAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS process);
extern LIST_ENTRY PsLoadedModuleList;
}

namespace {

constexpr ULONG kTag = 'udkb';
constexpr ULONG kMaxModuleName = 96;
constexpr ULONG kMaxModuleWalk = 1024;
constexpr ULONG kMaxTransfer = KDU_MAX_TRANSFER;

kc_kernel* g_channel = nullptr;
uint64_t g_image_base = 0;
uint64_t g_image_size = 0;
uint32_t g_windows_build = 0;
bool g_started = false;

// ---------------------------------------------------------------------------
// small helpers (no CRT)
// ---------------------------------------------------------------------------
void zero_memory(void* buffer, SIZE_T size) {
    auto* bytes = static_cast<UCHAR*>(buffer);
    for (SIZE_T index = 0; index < size; ++index) {
        bytes[index] = 0;
    }
}

void copy_memory(void* destination, const void* source, SIZE_T size) {
    auto* out = static_cast<UCHAR*>(destination);
    const auto* in = static_cast<const UCHAR*>(source);
    for (SIZE_T index = 0; index < size; ++index) {
        out[index] = in[index];
    }
}

bool is_kernel_pointer(uint64_t value) {
    return value >= 0xFFFF800000000000ull;
}

bool is_canonical(uint64_t value) {
    const uint64_t high = value >> 47;
    return high == 0 || high == 0x1FFFF;
}

char lower(char value) {
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value + 32) : value;
}

bool name_equals_ascii(const wchar_t* name, ULONG length, const char* wanted) {
    const ULONG chars = length / sizeof(wchar_t);
    ULONG index = 0;
    for (; index < chars && wanted[index]; ++index) {
        const wchar_t left = name[index];
        wchar_t lowered = left;
        if (left >= L'A' && left <= L'Z') {
            lowered = static_cast<wchar_t>(left + 32);
        }
        if (lowered != static_cast<wchar_t>(wanted[index])) {
            return false;
        }
    }
    return wanted[index] == '\0' && index == chars;
}

// ---------------------------------------------------------------------------
// physical memory
// ---------------------------------------------------------------------------
NTSTATUS physical_read(uint64_t address, void* buffer, SIZE_T size) {
    MM_COPY_ADDRESS copy_address{};
    copy_address.PhysicalAddress.QuadPart = static_cast<LONGLONG>(address);
    SIZE_T transferred = 0;
    const NTSTATUS status = MmCopyMemory(buffer, copy_address, size,
                                         MM_COPY_MEMORY_PHYSICAL, &transferred);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return transferred == size ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

NTSTATUS physical_write(uint64_t address, const void* buffer, SIZE_T size) {
    // Writes go through a non-cached mapping: the page tables of kernel images
    // are read-only, physical access ignores that by design.
    const uint64_t page_base = address & ~0xFFFull;
    const SIZE_T offset = static_cast<SIZE_T>(address - page_base);
    const SIZE_T map_size = offset + size;
    PHYSICAL_ADDRESS physical{};
    physical.QuadPart = static_cast<LONGLONG>(page_base);
    PVOID mapped =
        MmMapIoSpaceEx(physical, map_size, PAGE_READWRITE | PAGE_NOCACHE);
    if (!mapped) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    copy_memory(static_cast<UCHAR*>(mapped) + offset, buffer, size);
    MmUnmapIoSpace(mapped, map_size);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// page tables
// ---------------------------------------------------------------------------
constexpr uint64_t kPageMask = 0x000FFFFFFFFFF000ull;

NTSTATUS translate_address(uint64_t cr3, uint64_t virtual_address,
                           uint64_t* physical, uint64_t* span) {
    if (!is_canonical(virtual_address)) {
        return STATUS_INVALID_ADDRESS;
    }
    const uint64_t tables[4] = {
        (virtual_address >> 39) & 0x1FF, (virtual_address >> 30) & 0x1FF,
        (virtual_address >> 21) & 0x1FF, (virtual_address >> 12) & 0x1FF};
    uint64_t table = cr3 & kPageMask;
    for (int level = 0; level < 4; ++level) {
        uint64_t entry = 0;
        const NTSTATUS status = physical_read(
            table + tables[level] * sizeof(uint64_t), &entry, sizeof(entry));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if ((entry & 1) == 0) {
            return STATUS_NOT_FOUND;
        }
        if (level == 1 && (entry & 0x80)) {  // 1 GiB
            *physical = (entry & 0x000FFFFFC0000000ull) +
                        (virtual_address & 0x3FFFFFFFull);
            *span = 1ull << 30;
            return STATUS_SUCCESS;
        }
        if (level == 2 && (entry & 0x80)) {  // 2 MiB
            *physical = (entry & 0x000FFFFFFFE00000ull) +
                        (virtual_address & 0x1FFFFFull);
            *span = 1ull << 21;
            return STATUS_SUCCESS;
        }
        table = entry & kPageMask;
    }
    *physical = table + (virtual_address & 0xFFFull);
    *span = 0x1000;
    return STATUS_SUCCESS;
}

NTSTATUS virtual_read(uint64_t cr3, uint64_t address, void* buffer,
                      SIZE_T size) {
    auto* out = static_cast<UCHAR*>(buffer);
    SIZE_T done = 0;
    while (done < size) {
        uint64_t physical = 0;
        uint64_t span = 0;
        const NTSTATUS status =
            translate_address(cr3, address + done, &physical, &span);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        const uint64_t in_page = span - ((address + done) & (span - 1));
        const SIZE_T take = static_cast<SIZE_T>(
            in_page < (size - done) ? in_page : (size - done));
        const NTSTATUS read_status = physical_read(physical, out + done, take);
        if (!NT_SUCCESS(read_status)) {
            return read_status;
        }
        done += take;
    }
    return STATUS_SUCCESS;
}

NTSTATUS virtual_write(uint64_t cr3, uint64_t address, const void* buffer,
                       SIZE_T size) {
    const auto* in = static_cast<const UCHAR*>(buffer);
    SIZE_T done = 0;
    while (done < size) {
        uint64_t physical = 0;
        uint64_t span = 0;
        const NTSTATUS status =
            translate_address(cr3, address + done, &physical, &span);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        const uint64_t in_page = span - ((address + done) & (span - 1));
        const SIZE_T take = static_cast<SIZE_T>(
            in_page < (size - done) ? in_page : (size - done));
        const NTSTATUS write_status = physical_write(physical, in + done, take);
        if (!NT_SUCCESS(write_status)) {
            return write_status;
        }
        done += take;
    }
    return STATUS_SUCCESS;
}

uint64_t current_cr3() {
    return __readcr3() & kPageMask;
}

// ---------------------------------------------------------------------------
// process memory
// ---------------------------------------------------------------------------
struct ProcessSpace {
    uint32_t pid;
    uint64_t eprocess;
    uint64_t cr3;
    uint64_t peb;
};

NTSTATUS open_process(uint32_t pid, ProcessSpace* space) {
    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    zero_memory(space, sizeof(*space));
    space->pid = pid;
    space->eprocess = reinterpret_cast<uint64_t>(process);
    space->peb = reinterpret_cast<uint64_t>(PsGetProcessPeb(process));
    // KPROCESS.DirectoryTableBase is at offset 0x28 on x64.
    ULONG64 cr3 = 0;
    __try {
        cr3 = *reinterpret_cast<ULONG64*>(reinterpret_cast<UCHAR*>(process) +
                                          0x28);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        cr3 = 0;
    }
    ObDereferenceObject(process);
    if (!cr3 || !is_canonical(space->peb) || space->peb < 0x10000) {
        return STATUS_INVALID_PARAMETER;
    }
    // Validate: the candidate CR3 must resolve the PEB with a sane header.
    UCHAR header[0x20] = {};
    status = virtual_read(cr3, space->peb, header, sizeof(header));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    uint64_t image_base = 0;
    uint64_t ldr = 0;
    copy_memory(&image_base, header + 0x10, sizeof(image_base));
    copy_memory(&ldr, header + 0x18, sizeof(ldr));
    if (!is_canonical(image_base) || image_base < 0x10000 ||
        !is_canonical(ldr) || ldr < 0x10000) {
        return STATUS_INVALID_ADDRESS;
    }
    space->cr3 = cr3 & kPageMask;
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// module list
// ---------------------------------------------------------------------------
struct KduLdrEntry {
    LIST_ENTRY in_load_order;
    LIST_ENTRY in_memory_order;
    LIST_ENTRY in_initialization_order;
    PVOID dll_base;
    PVOID entry_point;
    ULONG size_of_image;
    UNICODE_STRING full_dll_name;
    UNICODE_STRING base_dll_name;
};

NTSTATUS find_module(const char* name, uint64_t* base, ULONG* size) {
    const uint64_t head = reinterpret_cast<uint64_t>(&PsLoadedModuleList);
    LIST_ENTRY* link = PsLoadedModuleList.Flink;
    ULONG guard = 0;
    while (reinterpret_cast<uint64_t>(link) != head && guard < kMaxModuleWalk) {
        ++guard;
        if (!is_kernel_pointer(reinterpret_cast<uint64_t>(link))) {
            return STATUS_INVALID_ADDRESS;
        }
        auto* entry = CONTAINING_RECORD(link, KduLdrEntry, in_load_order);
        if (entry->base_dll_name.Buffer && entry->base_dll_name.Length) {
            if (name_equals_ascii(entry->base_dll_name.Buffer,
                                  entry->base_dll_name.Length, name)) {
                *base = reinterpret_cast<uint64_t>(entry->dll_base);
                *size = entry->size_of_image;
                return STATUS_SUCCESS;
            }
        }
        link = link->Flink;
    }
    return STATUS_NOT_FOUND;
}

// ---------------------------------------------------------------------------
// ci.dll / g_CiOptions
// ---------------------------------------------------------------------------
struct SectionSpan {
    ULONG virtual_address;
    ULONG size;
    ULONG characteristics;
};

NTSTATUS find_ci_options(uint64_t* options_address, uint64_t* ci_base,
                         uint32_t* current) {
    uint64_t base = 0;
    ULONG size = 0;
    NTSTATUS status = find_module("ci.dll", &base, &size);
    if (!NT_SUCCESS(status)) {
        // Windows 7 keeps the flags in ntoskrnl.exe.
        status = find_module("ntoskrnl.exe", &base, &size);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    *ci_base = base;
    auto* image =
        static_cast<UCHAR*>(ExAllocatePoolWithTag(NonPagedPool, size, kTag));
    if (!image) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    zero_memory(image, size);
    status = virtual_read(current_cr3(), base, image, size);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(image, kTag);
        return status;
    }

    // Parse the export directory for CiInitialize.
    ULONG ci_initialize = 0;
    const auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        static_cast<ULONG>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > size) {
        ExFreePoolWithTag(image, kTag);
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(image + dos->e_lfanew);
    const auto& directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory.VirtualAddress && directory.Size &&
        directory.VirtualAddress + directory.Size <= size) {
        auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
            image + directory.VirtualAddress);
        auto* names = reinterpret_cast<ULONG*>(image + exports->AddressOfNames);
        auto* ordinals =
            reinterpret_cast<USHORT*>(image + exports->AddressOfNameOrdinals);
        auto* functions =
            reinterpret_cast<ULONG*>(image + exports->AddressOfFunctions);
        for (ULONG index = 0; index < exports->NumberOfNames; ++index) {
            const char* name =
                reinterpret_cast<const char*>(image + names[index]);
            if (name[0] == 'C' && name[1] == 'i' && name[2] == 'I' &&
                name[3] == 'n' && name[4] == 'i' && name[5] == 't' &&
                name[6] == '\0') {
                ci_initialize = functions[ordinals[index]];
                break;
            }
        }
    }

    uint64_t found = 0;
    if (ci_initialize) {
        // Scan CiInitialize for a call into the image (CipInitialize).
        ULONG call_target = 0;
        const ULONG limit =
            ci_initialize + 256 < size ? 256 : size - ci_initialize;
        for (ULONG offset = 0; offset + 5 <= limit; ++offset) {
            const UCHAR opcode = image[ci_initialize + offset];
            if (opcode != 0xE8) {
                continue;
            }
            LONG relative = 0;
            copy_memory(&relative, image + ci_initialize + offset + 1,
                        sizeof(relative));
            const LONG64 target =
                static_cast<LONG64>(ci_initialize) + offset + 5 + relative;
            if (target > 0 && static_cast<ULONG>(target) < size) {
                call_target = static_cast<ULONG>(target);
                break;
            }
        }
        if (call_target) {
            // CipInitialize: mov dword ptr [rip+rel32], ecx  (89 0D rel32)
            const ULONG limit2 =
                call_target + 256 < size ? 256 : size - call_target;
            for (ULONG offset = 0; offset + 6 <= limit2; ++offset) {
                const UCHAR* code = image + call_target + offset;
                if (!(code[0] == 0x89 && code[1] == 0x0D)) {
                    continue;
                }
                LONG relative = 0;
                copy_memory(&relative, code + 2, sizeof(relative));
                const LONG64 target =
                    static_cast<LONG64>(call_target) + offset + 6 + relative;
                if (target > 0 && static_cast<ULONG>(target) < size) {
                    found = base + static_cast<uint64_t>(target);
                    break;
                }
            }
        }
    }

    if (!found) {
        // Fallback: scan executable sections for the store instruction.
        auto* section = IMAGE_FIRST_SECTION(nt);
        for (USHORT index = 0; index < nt->FileHeader.NumberOfSections;
             ++index) {
            if ((section[index].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
                continue;
            }
            const ULONG start = section[index].VirtualAddress;
            const ULONG span = section[index].Misc.VirtualSize;
            for (ULONG offset = 0; offset + 6 <= span; ++offset) {
                const UCHAR* code = image + start + offset;
                if (!(code[0] == 0x89 && code[1] == 0x0D)) {
                    continue;
                }
                LONG relative = 0;
                copy_memory(&relative, code + 2, sizeof(relative));
                const LONG64 target =
                    static_cast<LONG64>(start) + offset + 6 + relative;
                if (target > 0 && static_cast<ULONG>(target) < size) {
                    found = base + static_cast<uint64_t>(target);
                    break;
                }
            }
            if (found) {
                break;
            }
        }
    }
    ExFreePoolWithTag(image, kTag);
    if (!found) {
        return STATUS_NOT_FOUND;
    }
    *options_address = found;
    uint32_t options = 0;
    status = virtual_read(current_cr3(), found, &options, sizeof(options));
    if (NT_SUCCESS(status)) {
        *current = options;
    }
    return status;
}

// ---------------------------------------------------------------------------
// RPC handlers
// ---------------------------------------------------------------------------
kc_status validate_header(const void* in, uint32_t in_len, uint32_t minimum,
                          uint32_t* payload_size) {
    if (!in || in_len < minimum) {
        return KC_ERR_PARAM;
    }
    const auto* header = static_cast<const kdu_rpc_header*>(in);
    if (header->magic != KDU_PAYLOAD_MAGIC || header->size != in_len) {
        return KC_ERR_MAGIC;
    }
    if (payload_size) {
        *payload_size = in_len - minimum;
    }
    return KC_OK;
}

kc_status reply(kdu_rpc_header* response, uint64_t out_cap, uint32_t out_len,
                uint32_t* out_cap_out, uint32_t* out_len_out) {
    (void)out_cap;
    *out_len_out = out_len;
    response->size = out_len;
    response->status = 0;
    return KC_OK;
}

kc_status handle_query(void*, uint16_t, const void* in, uint32_t in_len,
                       void* out, uint32_t* out_cap, uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_rpc_header), &payload);
    if (status != KC_OK) {
        return status;
    }
    if (!out || *out_cap < sizeof(kdu_query_info)) {
        return KC_ERR_PARAM;
    }
    auto* info = static_cast<kdu_query_info*>(out);
    zero_memory(info, sizeof(*info));
    info->header.magic = KDU_PAYLOAD_MAGIC;
    info->header.opcode = KDU_OP_QUERY;
    info->abi_major = KC_ABI_MAJOR;
    info->abi_minor = KC_ABI_MINOR;
    info->windows_build = g_windows_build;
    info->payload_base = g_image_base;
    info->payload_size = g_image_size;
    *out_cap = sizeof(*info);
    return reply(&info->header, *out_cap, sizeof(*info), out_cap, out_len);
}

kc_status handle_read_physical(void*, uint16_t, const void* in, uint32_t in_len,
                               void* out, uint32_t* out_cap,
                               uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_mem_request), &payload);
    if (status != KC_OK) {
        return status;
    }
    const auto* request = static_cast<const kdu_mem_request*>(in);
    const uint32_t size = request->size;
    if (size == 0 || size > kMaxTransfer || !out || *out_cap < size) {
        return KC_ERR_PARAM;
    }
    const NTSTATUS result = physical_read(request->address, out, size);
    if (!NT_SUCCESS(result)) {
        return KC_ERR_IO;
    }
    *out_cap = size;
    *out_len = size;
    return KC_OK;
}

kc_status handle_write_physical(void*, uint16_t, const void* in,
                                uint32_t in_len, void* out, uint32_t* out_cap,
                                uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_mem_request), &payload);
    if (status != KC_OK) {
        return status;
    }
    const auto* request = static_cast<const kdu_mem_request*>(in);
    const uint32_t size = request->size;
    if (size == 0 || size > kMaxTransfer || payload != size) {
        return KC_ERR_PARAM;
    }
    const NTSTATUS result =
        physical_write(request->address,
                       static_cast<const UCHAR*>(in) + sizeof(*request), size);
    if (!NT_SUCCESS(result)) {
        return KC_ERR_IO;
    }
    *out_cap = 0;
    *out_len = 0;
    return KC_OK;
}

kc_status handle_read_virtual(void*, uint16_t, const void* in, uint32_t in_len,
                              void* out, uint32_t* out_cap, uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_mem_request), &payload);
    if (status != KC_OK) {
        return status;
    }
    const auto* request = static_cast<const kdu_mem_request*>(in);
    const uint32_t size = request->size;
    if (size == 0 || size > kMaxTransfer || !out || *out_cap < size) {
        return KC_ERR_PARAM;
    }
    const NTSTATUS result =
        virtual_read(current_cr3(), request->address, out, size);
    if (!NT_SUCCESS(result)) {
        return KC_ERR_IO;
    }
    *out_cap = size;
    *out_len = size;
    return KC_OK;
}

kc_status handle_write_virtual(void*, uint16_t, const void* in, uint32_t in_len,
                               void* out, uint32_t* out_cap,
                               uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_mem_request), &payload);
    if (status != KC_OK) {
        return status;
    }
    const auto* request = static_cast<const kdu_mem_request*>(in);
    const uint32_t size = request->size;
    if (size == 0 || size > kMaxTransfer || payload != size) {
        return KC_ERR_PARAM;
    }
    const NTSTATUS result =
        virtual_write(current_cr3(), request->address,
                      static_cast<const UCHAR*>(in) + sizeof(*request), size);
    if (!NT_SUCCESS(result)) {
        return KC_ERR_IO;
    }
    *out_cap = 0;
    *out_len = 0;
    return KC_OK;
}

kc_status handle_translate(void*, uint16_t, const void* in, uint32_t in_len,
                           void* out, uint32_t* out_cap, uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_translate_request), &payload);
    if (status != KC_OK) {
        return status;
    }
    if (!out || *out_cap < sizeof(kdu_translate_request)) {
        return KC_ERR_PARAM;
    }
    const auto* request = static_cast<const kdu_translate_request*>(in);
    auto* response = static_cast<kdu_translate_request*>(out);
    zero_memory(response, sizeof(*response));
    uint64_t physical = 0;
    uint64_t span = 0;
    if (!NT_SUCCESS(translate_address(current_cr3(), request->address,
                                      &physical, &span))) {
        return KC_ERR_NOT_FOUND;
    }
    response->header.magic = KDU_PAYLOAD_MAGIC;
    response->header.opcode = KDU_OP_TRANSLATE;
    response->address = request->address;
    response->physical = physical;
    *out_cap = sizeof(*response);
    return reply(&response->header, *out_cap, sizeof(*response), out_cap,
                 out_len);
}

kc_status handle_process_cr3(void*, uint16_t, const void* in, uint32_t in_len,
                             void* out, uint32_t* out_cap, uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_cr3_request), &payload);
    if (status != KC_OK) {
        return status;
    }
    if (!out || *out_cap < sizeof(kdu_cr3_request)) {
        return KC_ERR_PARAM;
    }
    const auto* request = static_cast<const kdu_cr3_request*>(in);
    auto* response = static_cast<kdu_cr3_request*>(out);
    zero_memory(response, sizeof(*response));
    ProcessSpace space{};
    if (!NT_SUCCESS(open_process(request->pid, &space))) {
        return KC_ERR_NOT_FOUND;
    }
    response->header.magic = KDU_PAYLOAD_MAGIC;
    response->header.opcode = KDU_OP_PROCESS_CR3;
    response->pid = request->pid;
    response->cr3 = space.cr3;
    response->peb = space.peb;
    *out_cap = sizeof(*response);
    return reply(&response->header, *out_cap, sizeof(*response), out_cap,
                 out_len);
}

kc_status handle_read_process(void*, uint16_t, const void* in, uint32_t in_len,
                              void* out, uint32_t* out_cap, uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_process_request), &payload);
    if (status != KC_OK) {
        return status;
    }
    const auto* request = static_cast<const kdu_process_request*>(in);
    const uint32_t size = request->size;
    if (size == 0 || size > kMaxTransfer || !out || *out_cap < size) {
        return KC_ERR_PARAM;
    }
    ProcessSpace space{};
    if (!NT_SUCCESS(open_process(request->pid, &space))) {
        return KC_ERR_NOT_FOUND;
    }
    if (!NT_SUCCESS(virtual_read(space.cr3, request->address, out, size))) {
        return KC_ERR_IO;
    }
    *out_cap = size;
    *out_len = size;
    return KC_OK;
}

kc_status handle_write_process(void*, uint16_t, const void* in, uint32_t in_len,
                               void* out, uint32_t* out_cap,
                               uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_process_request), &payload);
    if (status != KC_OK) {
        return status;
    }
    const auto* request = static_cast<const kdu_process_request*>(in);
    const uint32_t size = request->size;
    if (size == 0 || size > kMaxTransfer || payload != size) {
        return KC_ERR_PARAM;
    }
    ProcessSpace space{};
    if (!NT_SUCCESS(open_process(request->pid, &space))) {
        return KC_ERR_NOT_FOUND;
    }
    if (!NT_SUCCESS(virtual_write(
            space.cr3, request->address,
            static_cast<const UCHAR*>(in) + sizeof(*request), size))) {
        return KC_ERR_IO;
    }
    *out_cap = 0;
    *out_len = 0;
    return KC_OK;
}

kc_status handle_dse_status(void*, uint16_t, const void* in, uint32_t in_len,
                            void* out, uint32_t* out_cap, uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_dse_request), &payload);
    if (status != KC_OK) {
        return status;
    }
    if (!out || *out_cap < sizeof(kdu_dse_request)) {
        return KC_ERR_PARAM;
    }
    auto* response = static_cast<kdu_dse_request*>(out);
    zero_memory(response, sizeof(*response));
    uint64_t address = 0;
    uint64_t ci_base = 0;
    uint32_t current = 0;
    if (!NT_SUCCESS(find_ci_options(&address, &ci_base, &current))) {
        return KC_ERR_NOT_FOUND;
    }
    response->header.magic = KDU_PAYLOAD_MAGIC;
    response->header.opcode = KDU_OP_DSE_STATUS;
    response->address = address;
    response->options = current;
    response->original = current;
    *out_cap = sizeof(*response);
    return reply(&response->header, *out_cap, sizeof(*response), out_cap,
                 out_len);
}

kc_status handle_dse_set(void*, uint16_t, const void* in, uint32_t in_len,
                         void* out, uint32_t* out_cap, uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_dse_request), &payload);
    if (status != KC_OK) {
        return status;
    }
    const auto* request = static_cast<const kdu_dse_request*>(in);
    if (!out || *out_cap < sizeof(kdu_dse_request)) {
        return KC_ERR_PARAM;
    }
    auto* response = static_cast<kdu_dse_request*>(out);
    zero_memory(response, sizeof(*response));
    uint64_t address = request->address;
    uint64_t ci_base = 0;
    uint32_t current = 0;
    if (!address) {
        if (!NT_SUCCESS(find_ci_options(&address, &ci_base, &current))) {
            return KC_ERR_NOT_FOUND;
        }
    } else if (!NT_SUCCESS(virtual_read(current_cr3(), address, &current,
                                        sizeof(current)))) {
        return KC_ERR_IO;
    }
    const uint32_t original = current;
    if (!NT_SUCCESS(virtual_write(current_cr3(), address, &request->options,
                                  sizeof(request->options)))) {
        return KC_ERR_IO;
    }
    response->header.magic = KDU_PAYLOAD_MAGIC;
    response->header.opcode = KDU_OP_DSE_SET;
    response->address = address;
    response->options = request->options;
    response->original = original;
    *out_cap = sizeof(*response);
    return reply(&response->header, *out_cap, sizeof(*response), out_cap,
                 out_len);
}

kc_status handle_enum_modules(void*, uint16_t, const void* in, uint32_t in_len,
                              void* out, uint32_t* out_cap, uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_module_request), &payload);
    if (status != KC_OK) {
        return status;
    }
    if (!out || *out_cap < sizeof(kdu_module_info)) {
        return KC_ERR_PARAM;
    }
    const auto* request = static_cast<const kdu_module_request*>(in);
    auto* response = static_cast<kdu_module_info*>(out);
    zero_memory(response, sizeof(*response));
    const uint64_t head = reinterpret_cast<uint64_t>(&PsLoadedModuleList);
    LIST_ENTRY* link = PsLoadedModuleList.Flink;
    ULONG guard = 0;
    ULONG index = 0;
    while (reinterpret_cast<uint64_t>(link) != head && guard < kMaxModuleWalk) {
        ++guard;
        if (!is_kernel_pointer(reinterpret_cast<uint64_t>(link))) {
            return KC_ERR_IO;
        }
        auto* entry = CONTAINING_RECORD(link, KduLdrEntry, in_load_order);
        if (index == request->index) {
            if (entry->base_dll_name.Buffer && entry->base_dll_name.Length) {
                const ULONG chars =
                    entry->base_dll_name.Length / sizeof(wchar_t);
                const ULONG limit =
                    chars < (kMaxModuleName - 1) ? chars : (kMaxModuleName - 1);
                for (ULONG position = 0; position < limit; ++position) {
                    const wchar_t character =
                        entry->base_dll_name.Buffer[position];
                    response->name[position] =
                        character < 0x80 ? static_cast<char>(character) : '?';
                }
            }
            response->header.magic = KDU_PAYLOAD_MAGIC;
            response->header.opcode = KDU_OP_ENUM_MODULES;
            response->base = reinterpret_cast<uint64_t>(entry->dll_base);
            response->size = entry->size_of_image;
            *out_cap = sizeof(*response);
            return reply(&response->header, *out_cap, sizeof(*response),
                         out_cap, out_len);
        }
        ++index;
        link = link->Flink;
    }
    return KC_ERR_NOT_FOUND;
}

kc_status handle_unload(void*, uint16_t, const void* in, uint32_t in_len,
                        void* out, uint32_t* out_cap, uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_rpc_header), &payload);
    if (status != KC_OK) {
        return status;
    }
    if (g_channel) {
        kc_kernel_stop(g_channel);
        kc_kernel_destroy(g_channel);
        g_channel = nullptr;
    }
    g_started = false;
    *out_cap = 0;
    *out_len = 0;
    return KC_OK;
}

constexpr struct {
    uint16_t opcode;
    kc_handler_fn handler;
} kHandlers[] = {
    {KDU_OP_PING, nullptr},
    {KDU_OP_QUERY, &handle_query},
    {KDU_OP_READ_PHYSICAL, &handle_read_physical},
    {KDU_OP_WRITE_PHYSICAL, &handle_write_physical},
    {KDU_OP_READ_VIRTUAL, &handle_read_virtual},
    {KDU_OP_WRITE_VIRTUAL, &handle_write_virtual},
    {KDU_OP_TRANSLATE, &handle_translate},
    {KDU_OP_READ_PROCESS, &handle_read_process},
    {KDU_OP_WRITE_PROCESS, &handle_write_process},
    {KDU_OP_PROCESS_CR3, &handle_process_cr3},
    {KDU_OP_DSE_STATUS, &handle_dse_status},
    {KDU_OP_DSE_SET, &handle_dse_set},
    {KDU_OP_ENUM_MODULES, &handle_enum_modules},
    {KDU_OP_UNLOAD, &handle_unload},
};

kc_status handle_ping(void*, uint16_t, const void* in, uint32_t in_len,
                      void* out, uint32_t* out_cap, uint32_t* out_len) {
    uint32_t payload = 0;
    kc_status status =
        validate_header(in, in_len, sizeof(kdu_rpc_header), &payload);
    if (status != KC_OK) {
        return status;
    }
    *out_cap = 0;
    *out_len = 0;
    return KC_OK;
}

}  // namespace

extern "C" NTSTATUS kdu_payload_entry(void* parameter) {
    if (!parameter ||
        !is_kernel_pointer(reinterpret_cast<uint64_t>(parameter))) {
        return STATUS_INVALID_PARAMETER;
    }
    auto* params = static_cast<kdu_payload_params*>(parameter);
    if (params->magic != KDU_PAYLOAD_PARAM_MAGIC ||
        params->size != sizeof(kdu_payload_params) || params->image_size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    g_image_base = params->image_base;
    g_image_size = params->image_size;
    g_windows_build = params->windows_build;

    kc_kernel_config config{};
    config.max_payload = KDU_MAX_TRANSFER;
    config.flags = KC_KFLAG_BLOCK_ON_BACKPRESSURE;
    kc_status status =
        kc_kernel_create(&params->bootstrap, &config, &g_channel);
    if (status != KC_OK) {
        return STATUS_UNSUCCESSFUL;
    }
    for (const auto& entry : kHandlers) {
        if (entry.handler == nullptr) {
            continue;
        }
        if (kc_kernel_register(g_channel, entry.opcode, entry.handler,
                               nullptr) != KC_OK) {
            kc_kernel_destroy(g_channel);
            g_channel = nullptr;
            return STATUS_UNSUCCESSFUL;
        }
    }
    if (kc_kernel_register(g_channel, KDU_OP_PING, &handle_ping, nullptr) !=
        KC_OK) {
        kc_kernel_destroy(g_channel);
        g_channel = nullptr;
        return STATUS_UNSUCCESSFUL;
    }
    status = kc_kernel_start(g_channel);
    if (status != KC_OK) {
        kc_kernel_destroy(g_channel);
        g_channel = nullptr;
        return STATUS_UNSUCCESSFUL;
    }
    g_started = true;
    return STATUS_SUCCESS;
}
