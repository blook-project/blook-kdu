// blook-kdu: logging setup (spdlog).
#pragma once

#include <spdlog/spdlog.h>

#include <memory>
#include <string>
#include <string_view>

namespace blook::kdu::core {

// Initialise the global "kdu" logger. Idempotent; later calls only adjust the
// level / add a file sink.
void init_logging(std::string_view level, std::string_view log_file = {});

// Effective logger (never null after init_logging; a default logger before).
std::shared_ptr<spdlog::logger> logger();

// True when the level name is recognised.
bool is_valid_log_level(std::string_view level);

}  // namespace blook::kdu::core

#define KDU_LOGGER ::blook::kdu::core::logger()

#define KDU_LOG_TRACE(...) SPDLOG_LOGGER_TRACE(KDU_LOGGER, __VA_ARGS__)
#define KDU_LOG_DEBUG(...) SPDLOG_LOGGER_DEBUG(KDU_LOGGER, __VA_ARGS__)
#define KDU_LOG_INFO(...) SPDLOG_LOGGER_INFO(KDU_LOGGER, __VA_ARGS__)
#define KDU_LOG_WARN(...) SPDLOG_LOGGER_WARN(KDU_LOGGER, __VA_ARGS__)
#define KDU_LOG_ERROR(...) SPDLOG_LOGGER_ERROR(KDU_LOGGER, __VA_ARGS__)
