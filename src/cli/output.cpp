// blook-kdu CLI: output helpers implementation.
#include "cli/output.h"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <vector>

#include "exploits/common/iexploit.h"

namespace blook::kdu::cli {
namespace {

bool g_color = false;

std::string wrap(std::string_view text, const char* code) {
    if (!g_color) {
        return std::string(text);
    }
    return std::string(code) + std::string(text) + "\x1b[0m";
}

nlohmann::json info_to_json(const blook::kdu::SessionInfo& info) {
    nlohmann::json result;
    result["version"] = info.version;
    result["exploit"] = info.exploit;
    result["driver_name"] = info.driver_name;
    result["service_name"] = info.service_name;
    result["backend"] = info.backend;
    result["windows_build"] = info.windows_build;
    result["payload_mapped"] = info.payload_mapped;
    result["payload_base"] = fmt::format("0x{:x}", info.payload_base);
    result["payload_size"] = info.payload_size;
    result["capabilities"] = info.capabilities;
    return result;
}

}  // namespace

void set_color_enabled(bool enabled) {
    g_color = enabled;
}
bool color_enabled() {
    return g_color;
}

std::string green(std::string_view text) {
    return wrap(text, "\x1b[32m");
}
std::string red(std::string_view text) {
    return wrap(text, "\x1b[31m");
}
std::string yellow(std::string_view text) {
    return wrap(text, "\x1b[33m");
}
std::string cyan(std::string_view text) {
    return wrap(text, "\x1b[36m");
}
std::string bold(std::string_view text) {
    return wrap(text, "\x1b[1m");
}
std::string dim(std::string_view text) {
    return wrap(text, "\x1b[2m");
}

std::string render_table(const std::vector<std::vector<std::string>>& rows,
                         bool header) {
    if (rows.empty()) {
        return {};
    }
    std::size_t columns = 0;
    for (const auto& row : rows) {
        columns = std::max(columns, row.size());
    }
    std::vector<std::size_t> widths(columns, 0);
    for (const auto& row : rows) {
        for (std::size_t index = 0; index < row.size(); ++index) {
            widths[index] = std::max(widths[index], row[index].size());
        }
    }
    std::string out;
    for (std::size_t index = 0; index < rows.size(); ++index) {
        const auto& row = rows[index];
        for (std::size_t column = 0; column < row.size(); ++column) {
            out += row[column];
            if (column + 1 < row.size()) {
                out +=
                    std::string(widths[column] - row[column].size() + 2, ' ');
            }
        }
        out += '\n';
        if (header && index == 0) {
            std::size_t total = 0;
            for (std::size_t column = 0; column < columns; ++column) {
                total += widths[column];
            }
            total += 2 * (columns - 1);
            out += std::string(total, '-');
            out += '\n';
        }
    }
    return out;
}

std::string hexdump(std::span<const std::uint8_t> bytes, std::uint64_t base) {
    std::string out;
    constexpr std::size_t kPerLine = 16;
    for (std::size_t offset = 0; offset < bytes.size(); offset += kPerLine) {
        const auto count =
            std::min<std::size_t>(kPerLine, bytes.size() - offset);
        std::string hex;
        std::string ascii;
        for (std::size_t index = 0; index < kPerLine; ++index) {
            if (index < count) {
                const auto value = bytes[offset + index];
                hex += fmt::format("{:02x} ", value);
                ascii += static_cast<char>(value >= 0x20 && value < 0x7F ? value
                                                                         : '.');
            } else {
                hex += "   ";
            }
            if (index == 7) {
                hex += ' ';
            }
        }
        out += fmt::format("{:08x}  {} |{}|\n", base + offset, hex, ascii);
    }
    return out;
}

std::string human_size(std::uint64_t bytes) {
    constexpr const char* kUnits[] = {"B", "KiB", "MiB", "GiB"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < 4) {
        value /= 1024.0;
        ++unit;
    }
    if (unit == 0) {
        return fmt::format("{} B", bytes);
    }
    return fmt::format("{:.1f} {} ({} bytes)", value, kUnits[unit], bytes);
}

std::string format_status(blook::kdu::Status status) {
    const auto* text = blook::kdu::status_to_string(status);
    if (status == blook::kdu::Status::ok) {
        return green(text);
    }
    return red(text);
}

std::string json_escape(std::string_view text) {
    // Localized Windows messages can contain non-UTF-8 bytes; replace them
    // instead of throwing so --json output is always valid.
    const auto dumped =
        nlohmann::json(std::string(text))
            .dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    // Strip the surrounding quotes: callers embed this inside hand-written
    // JSON strings.
    if (dumped.size() >= 2) {
        return dumped.substr(1, dumped.size() - 2);
    }
    return dumped;
}

std::string session_info_json(const blook::kdu::SessionInfo& info) {
    return info_to_json(info).dump(2);
}

std::string modules_json(const std::vector<blook::kdu::ModuleInfo>& modules) {
    nlohmann::json array = nlohmann::json::array();
    for (const auto& module : modules) {
        nlohmann::json item;
        item["name"] = module.name;
        item["path"] = module.path;
        item["base"] = fmt::format("0x{:x}", module.base);
        item["size"] = module.size;
        array.push_back(std::move(item));
    }
    return array.dump(2);
}

std::string dse_json(const blook::kdu::DseState& state) {
    nlohmann::json item;
    item["enabled"] = state.enabled;
    item["options"] = fmt::format("0x{:x}", state.options);
    item["options_address"] = fmt::format("0x{:x}", state.options_address);
    return item.dump(2);
}

std::string cleanup_json(const blook::kdu::CleanupReport& report) {
    nlohmann::json item;
    item["clean"] = report.clean;
    item["actions"] = report.actions;
    item["residuals"] = report.residuals;
    return item.dump(2);
}

std::string traces_json(const blook::kdu::TraceReport& report) {
    nlohmann::json item;
    item["clean"] = report.clean();
    nlohmann::json findings = nlohmann::json::array();
    for (const auto& finding : report.findings) {
        nlohmann::json entry;
        entry["category"] = finding.category;
        entry["description"] = finding.description;
        entry["location"] = finding.location;
        entry["cleaned"] = finding.cleaned;
        findings.push_back(std::move(entry));
    }
    item["findings"] = std::move(findings);
    return item.dump(2);
}

std::string exploits_json() {
    nlohmann::json array = nlohmann::json::array();
    for (const auto& descriptor : blook::kdu::exploits::all_exploits()) {
        const auto& info = descriptor.info();
        nlohmann::json item;
        item["id"] = info.id;
        item["name"] = info.display_name;
        item["description"] = info.description;
        item["vendor"] = info.vendor;
        item["cve"] = info.cve;
        item["driver"] = info.driver_file;
        item["service"] = info.service_name;
        item["device"] = info.device_name;
        item["capabilities"] =
            blook::kdu::exploits::capability_names(info.capabilities);
        item["min_build"] = info.min_build;
        item["max_build"] = info.max_build;
        item["unsafe_physical_holes"] = info.unsafe_physical_holes;
        array.push_back(std::move(item));
    }
    return array.dump(2);
}

}  // namespace blook::kdu::cli
