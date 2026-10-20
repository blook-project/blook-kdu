// blook-kdu: logging setup implementation.
#include "core/log.h"

#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <algorithm>
#include <mutex>

namespace blook::kdu::core {
namespace {

std::mutex g_mutex;
std::shared_ptr<spdlog::logger> g_logger;

spdlog::level::level_enum parse_level(std::string_view level) {
    using spdlog::level::level_enum;
    if (level == "trace")
        return level_enum::trace;
    if (level == "debug")
        return level_enum::debug;
    if (level == "info")
        return level_enum::info;
    if (level == "warn" || level == "warning")
        return level_enum::warn;
    if (level == "error")
        return level_enum::err;
    if (level == "critical")
        return level_enum::critical;
    return level_enum::off;
}

}  // namespace

bool is_valid_log_level(std::string_view level) {
    return level == "trace" || level == "debug" || level == "info" ||
           level == "warn" || level == "warning" || level == "error" ||
           level == "critical" || level == "off";
}

void init_logging(std::string_view level, std::string_view log_file) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_logger) {
        auto sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        g_logger = std::make_shared<spdlog::logger>("kdu", std::move(sink));
        g_logger->set_pattern("[%^%l%$] %v");
        spdlog::register_logger(g_logger);
    }
    g_logger->set_level(parse_level(level));
    if (!log_file.empty()) {
        try {
            auto file_sink =
                std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                    std::string(log_file), 4 * 1024 * 1024, 3);
            file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
            g_logger->sinks().push_back(std::move(file_sink));
        } catch (const std::exception&) {
            // Logging is best-effort; never fail an operation over a file sink.
        }
    }
}

std::shared_ptr<spdlog::logger> logger() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_logger) {
        auto sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        g_logger = std::make_shared<spdlog::logger>("kdu", std::move(sink));
        g_logger->set_pattern("[%^%l%$] %v");
        g_logger->set_level(spdlog::level::warn);
    }
    return g_logger;
}

}  // namespace blook::kdu::core
