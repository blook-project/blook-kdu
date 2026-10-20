// blook-kdu CLI: output helpers (colors, tables, hexdump, JSON).
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "blook/kdu/kdu.h"

namespace blook::kdu::cli {

// ANSI color helpers. Automatically disabled when not attached to a terminal or
// when NO_COLOR is set.
void set_color_enabled(bool enabled);
bool color_enabled();
std::string green(std::string_view text);
std::string red(std::string_view text);
std::string yellow(std::string_view text);
std::string cyan(std::string_view text);
std::string bold(std::string_view text);
std::string dim(std::string_view text);

// A simple aligned table. `rows` may include a header as the first row.
std::string render_table(const std::vector<std::vector<std::string>>& rows,
                         bool header = true);

// Classic hexdump with an ASCII gutter.
std::string hexdump(std::span<const std::uint8_t> bytes, std::uint64_t base);

// "1234" -> "1 KiB (1234 bytes)"
std::string human_size(std::uint64_t bytes);

std::string format_status(blook::kdu::Status status);

// JSON serialisation helpers (nlohmann_json, kept in the .cpp).
std::string json_escape(std::string_view text);
std::string session_info_json(const blook::kdu::SessionInfo& info);
std::string modules_json(const std::vector<blook::kdu::ModuleInfo>& modules);
std::string dse_json(const blook::kdu::DseState& state);
std::string cleanup_json(const blook::kdu::CleanupReport& report);
std::string traces_json(const blook::kdu::TraceReport& report);
std::string exploits_json();

}  // namespace blook::kdu::cli
