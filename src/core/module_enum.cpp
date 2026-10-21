// blook-kdu: kernel module enumeration implementation.
#include "core/module_enum.h"

#include <windows.h>
#include <psapi.h>
#include <winternl.h>

#include <algorithm>
#include <cstring>
#include <vector>

#include "core/win32.h"

namespace blook::kdu::core {
namespace {

constexpr ULONG kSystemModuleInformation = 11;

using NtQuerySystemInformationFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

NtQuerySystemInformationFn nt_query_system_information() {
    static const auto fn =
        reinterpret_cast<NtQuerySystemInformationFn>(::GetProcAddress(
            ::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    return fn;
}

struct ModuleInformation {
    HANDLE section;
    PVOID mapped_base;
    PVOID image_base;
    ULONG image_size;
    ULONG flags;
    USHORT load_order_index;
    USHORT init_order_index;
    USHORT load_count;
    USHORT offset_to_file_name;
    UCHAR full_path_name[256];
};

struct ModuleInformationList {
    ULONG number_of_modules;
    ModuleInformation modules[1];
};

std::string file_name_of(const ModuleInformation& module) {
    const char* path = reinterpret_cast<const char*>(module.full_path_name);
    const auto* name =
        path + std::min<std::size_t>(module.offset_to_file_name, 255);
    return std::string(name);
}

}  // namespace

Result<std::vector<KernelModuleEntry>> enum_kernel_modules() {
    const auto fn = nt_query_system_information();
    if (!fn) {
        return Result<std::vector<KernelModuleEntry>>::fail(
            Status::not_supported, "NtQuerySystemInformation unavailable");
    }
    ULONG size = 1 << 20;
    std::vector<std::uint8_t> buffer;
    for (int attempt = 0; attempt < 8; ++attempt) {
        buffer.resize(size);
        ULONG needed = 0;
        const LONG status =
            fn(kSystemModuleInformation, buffer.data(), size, &needed);
        if (status >= 0) {
            break;
        }
        if (static_cast<ULONG>(status) != 0xC0000004ul) {
            return Result<std::vector<KernelModuleEntry>>::fail(
                nt_status_status(status),
                "NtQuerySystemInformation(SystemModuleInformation) failed: " +
                    format_nt_status(status));
        }
        size = needed > size ? needed + 0x10000 : size * 2;
        if (attempt == 7) {
            return Result<std::vector<KernelModuleEntry>>::fail(
                Status::no_memory, "module list keeps growing");
        }
    }
    const auto* list =
        reinterpret_cast<const ModuleInformationList*>(buffer.data());
    std::vector<KernelModuleEntry> modules;
    modules.reserve(list->number_of_modules);
    for (ULONG index = 0; index < list->number_of_modules; ++index) {
        const auto& module = list->modules[index];
        KernelModuleEntry entry;
        entry.name = file_name_of(module);
        entry.path = reinterpret_cast<const char*>(module.full_path_name);
        entry.base = reinterpret_cast<std::uint64_t>(module.image_base);
        entry.size = module.image_size;
        modules.push_back(std::move(entry));
    }
    // Windows 11 26100 zeroes ImageBase for unprivileged
    // SystemModuleInformation callers on some configurations; EnumDeviceDrivers
    // still reports the loaded base, so use it as a fallback.
    bool any_base = false;
    for (const auto& module : modules) {
        if (module.base != 0) {
            any_base = true;
            break;
        }
    }
    if (!any_base) {
        std::vector<KernelModuleEntry> fallback;
        DWORD needed = 0;
        ::EnumDeviceDrivers(nullptr, 0, &needed);
        if (needed != 0) {
            std::vector<LPVOID> drivers(needed / sizeof(LPVOID) + 1);
            if (::EnumDeviceDrivers(
                    drivers.data(),
                    static_cast<DWORD>(drivers.size() * sizeof(LPVOID)),
                    &needed)) {
                const auto count = needed / sizeof(LPVOID);
                char name[MAX_PATH] = {};
                char path[MAX_PATH] = {};
                for (std::size_t index = 0; index < count; ++index) {
                    KernelModuleEntry entry;
                    if (!::GetDeviceDriverBaseNameA(drivers[index], name,
                                                    MAX_PATH)) {
                        continue;
                    }
                    entry.name = name;
                    if (::GetDeviceDriverFileNameA(drivers[index], path,
                                                   MAX_PATH)) {
                        entry.path = path;
                    }
                    entry.base =
                        reinterpret_cast<std::uint64_t>(drivers[index]);
                    entry.size = 0;
                    fallback.push_back(std::move(entry));
                }
            }
        }
        if (!fallback.empty()) {
            return Result<std::vector<KernelModuleEntry>>::ok(
                std::move(fallback));
        }
    }
    return Result<std::vector<KernelModuleEntry>>::ok(std::move(modules));
}

const KernelModuleEntry* find_module(
    const std::vector<KernelModuleEntry>& modules, std::string_view name) {
    std::string lowered(name);
    std::transform(
        lowered.begin(), lowered.end(), lowered.begin(),
        [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    for (const auto& module : modules) {
        std::string module_name = module.name;
        std::transform(
            module_name.begin(), module_name.end(), module_name.begin(),
            [](unsigned char c) { return static_cast<char>(::tolower(c)); });
        if (module_name == lowered) {
            return &module;
        }
    }
    return nullptr;
}

}  // namespace blook::kdu::core
