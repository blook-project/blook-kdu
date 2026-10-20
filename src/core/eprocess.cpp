// blook-kdu: EPROCESS / PEB discovery implementation.
#include "core/eprocess.h"

#include <windows.h>
#include <winternl.h>

#include <cstring>
#include <vector>

#include "core/page_table.h"
#include "core/win32.h"

namespace blook::kdu::core {
namespace {

constexpr ULONG kSystemExtendedHandleInformation = 64;
constexpr ULONG kProcessBasicInformation = 0;

using NtQuerySystemInformationFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG,
                                                 PULONG);

NtQuerySystemInformationFn nt_query_system_information() {
    static const auto fn =
        reinterpret_cast<NtQuerySystemInformationFn>(::GetProcAddress(
            ::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    return fn;
}

NtQueryInformationProcessFn nt_query_information_process() {
    static const auto fn =
        reinterpret_cast<NtQueryInformationProcessFn>(::GetProcAddress(
            ::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    return fn;
}

struct HandleTableEntry {
    PVOID object;
    ULONG_PTR unique_process_id;
    ULONG_PTR handle_value;
    ULONG granted_access;
    USHORT creator_back_trace_index;
    USHORT object_type_index;
    ULONG handle_attributes;
    ULONG reserved;
};

struct HandleInformation {
    ULONG_PTR number_of_handles;
    ULONG_PTR reserved;
    HandleTableEntry handles[1];
};

Result<std::vector<std::uint8_t>> query_handle_table() {
    const auto fn = nt_query_system_information();
    if (!fn) {
        return Result<std::vector<std::uint8_t>>::fail(
            Status::not_supported, "NtQuerySystemInformation unavailable");
    }
    ULONG size = 1 << 20;
    std::vector<std::uint8_t> buffer;
    for (int attempt = 0; attempt < 8; ++attempt) {
        buffer.resize(size);
        ULONG needed = 0;
        const LONG status =
            fn(kSystemExtendedHandleInformation, buffer.data(), size, &needed);
        if (status >= 0) {
            return Result<std::vector<std::uint8_t>>::ok(std::move(buffer));
        }
        // STATUS_INFO_LENGTH_MISMATCH
        if (static_cast<ULONG>(status) != 0xC0000004ul) {
            return Result<std::vector<std::uint8_t>>::fail(
                nt_status_status(status),
                "NtQuerySystemInformation failed: " + format_nt_status(status));
        }
        size = needed > size ? needed + 0x10000 : size * 2;
    }
    return Result<std::vector<std::uint8_t>>::fail(
        Status::no_memory, "handle table query buffer kept growing");
}

}  // namespace

Result<std::uint64_t> find_eprocess(std::uint32_t pid) {
    UniqueHandle process(
        ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process.valid()) {
        const DWORD error = ::GetLastError();
        return Result<std::uint64_t>::fail(
            win32_status(error),
            "OpenProcess failed: " + format_win32_error(error));
    }
    auto table = query_handle_table();
    if (!table) {
        return Result<std::uint64_t>::fail(table.error().code,
                                           table.error().message);
    }
    const auto* info =
        reinterpret_cast<const HandleInformation*>(table->data());
    const auto current_pid = static_cast<ULONG_PTR>(::GetCurrentProcessId());
    const auto handle = reinterpret_cast<ULONG_PTR>(process.get());
    for (ULONG_PTR index = 0; index < info->number_of_handles; ++index) {
        const auto& entry = info->handles[index];
        if (entry.unique_process_id != current_pid) {
            continue;
        }
        if (entry.handle_value != handle) {
            continue;
        }
        // Object pointers may carry tag bits in the low 3 bits.
        const auto value = reinterpret_cast<ULONG_PTR>(entry.object) &
                           0xFFFF'FFFF'FFFF'FFF8ull;
        if (value == 0) {
            break;
        }
        return Result<std::uint64_t>::ok(static_cast<std::uint64_t>(value));
    }
    return Result<std::uint64_t>::fail(
        Status::not_found, "EPROCESS pointer not found in handle table");
}

Result<std::uint64_t> query_process_peb(std::uint32_t pid) {
    UniqueHandle process(
        ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process.valid()) {
        const DWORD error = ::GetLastError();
        return Result<std::uint64_t>::fail(
            win32_status(error),
            "OpenProcess failed: " + format_win32_error(error));
    }
    const auto fn = nt_query_information_process();
    if (!fn) {
        return Result<std::uint64_t>::fail(
            Status::not_supported, "NtQueryInformationProcess unavailable");
    }
    PROCESS_BASIC_INFORMATION info{};
    ULONG needed = 0;
    const LONG status = fn(process.get(), kProcessBasicInformation, &info,
                           sizeof(info), &needed);
    if (status < 0) {
        return Result<std::uint64_t>::fail(
            nt_status_status(status),
            "NtQueryInformationProcess failed: " + format_nt_status(status));
    }
    const auto peb = reinterpret_cast<std::uint64_t>(info.PebBaseAddress);
    if (peb == 0) {
        return Result<std::uint64_t>::fail(Status::not_found,
                                           "process has no PEB");
    }
    return Result<std::uint64_t>::ok(peb);
}

Result<std::uint64_t> query_process_image_base(std::uint32_t pid) {
    UniqueHandle process(::OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!process.valid()) {
        const DWORD error = ::GetLastError();
        return Result<std::uint64_t>::fail(
            win32_status(error),
            "OpenProcess(VM_READ) failed: " + format_win32_error(error));
    }
    auto peb = query_process_peb(pid);
    if (!peb) {
        return Result<std::uint64_t>::fail(peb.error().code,
                                           peb.error().message);
    }
    std::uint64_t image_base = 0;
    SIZE_T read = 0;
    if (!::ReadProcessMemory(
            process.get(),
            reinterpret_cast<LPCVOID>(peb.value() + kPebImageBaseAddressOffset),
            &image_base, sizeof(image_base), &read) ||
        read != sizeof(image_base)) {
        return Result<std::uint64_t>::fail(Status::access_denied,
                                           "cannot read PEB.ImageBaseAddress");
    }
    return Result<std::uint64_t>::ok(image_base);
}

bool validate_process_cr3(const PhysicalReadFn& read, std::uint64_t cr3,
                          std::uint64_t peb, std::uint64_t expected_image) {
    if (!read || cr3 == 0 || !is_canonical_address(peb) || peb < 0x10000) {
        return false;
    }
    PageTableWalker walker(cr3, read);
    std::uint8_t bytes[0x20] = {};
    auto result = walker.read(peb, bytes, sizeof(bytes));
    if (!result) {
        return false;
    }
    std::uint64_t image_base = 0;
    std::uint64_t ldr = 0;
    std::memcpy(&image_base, bytes + kPebImageBaseAddressOffset,
                sizeof(image_base));
    std::memcpy(&ldr, bytes + kPebLdrOffset, sizeof(ldr));
    if (!is_canonical_address(image_base) || image_base < 0x10000 ||
        !is_canonical_address(ldr) || ldr < 0x10000) {
        return false;
    }
    if (expected_image != 0 && image_base != expected_image) {
        return false;
    }
    return true;
}

}  // namespace blook::kdu::core
