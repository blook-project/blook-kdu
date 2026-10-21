// blook-kdu CLI: shared context implementation.
#include "cli/context.h"

#include <cstdio>
#include <cstring>

#include "cli/output.h"
#include "core/win32.h"

namespace blook::kdu::cli {

blook::kdu::Session& Context::ensure_session() {
    if (session) {
        return *session;
    }
    blook::kdu::OpenOptions open_options;
    open_options.exploit = options.exploit;
    open_options.use_payload = options.use_payload;
    open_options.allow_driver_only =
        options.driver_only || !options.use_payload;
    if (!options.driver_only) {
        open_options.allow_driver_only = true;
    }
    open_options.log_level = options.log_level;
    open_options.restore_dse_on_close = !options.keep_dse;
    auto opened = blook::kdu::kdu_open(open_options);
    if (!opened) {
        throw CliError(opened.error().code, opened.error().message);
    }
    session = std::move(opened.value());
    return *session;
}

void Context::close_session() {
    if (session) {
        (void)session->close();
        session.reset();
    }
}

std::uint64_t parse_u64(std::string_view text) {
    std::string value(text);
    if (value.empty()) {
        throw CliError(blook::kdu::Status::invalid_argument,
                       "empty numeric value");
    }
    int base = 10;
    if (value.size() > 2 && (value[0] == '0') &&
        (value[1] == 'x' || value[1] == 'X')) {
        base = 16;
        value = value.substr(2);
    } else if (value.back() == 'h' || value.back() == 'H') {
        base = 16;
        value.pop_back();
    }
    try {
        std::size_t consumed = 0;
        const auto result = std::stoull(value, &consumed, base);
        if (consumed != value.size()) {
            throw std::invalid_argument("trailing characters");
        }
        return result;
    } catch (const std::exception&) {
        throw CliError(blook::kdu::Status::invalid_argument,
                       "invalid number: '" + std::string(text) + "'");
    }
}

std::uint32_t parse_u32(std::string_view text) {
    const auto value = parse_u64(text);
    if (value > 0xFFFF'FFFFull) {
        throw CliError(blook::kdu::Status::invalid_argument,
                       "value does not fit in 32 bits");
    }
    return static_cast<std::uint32_t>(value);
}

std::vector<std::uint8_t> parse_hex_bytes(std::string_view text) {
    std::string digits;
    for (char character : text) {
        if (character == ' ' || character == '\t' || character == ',' ||
            character == '-') {
            continue;
        }
        if (!std::isxdigit(static_cast<unsigned char>(character))) {
            throw CliError(blook::kdu::Status::invalid_argument,
                           "invalid hex byte string");
        }
        digits.push_back(character);
    }
    if (digits.size() % 2 != 0) {
        throw CliError(blook::kdu::Status::invalid_argument,
                       "hex byte string must have an even number of digits");
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(digits.size() / 2);
    for (std::size_t index = 0; index < digits.size(); index += 2) {
        const auto pair = digits.substr(index, 2);
        bytes.push_back(
            static_cast<std::uint8_t>(std::stoul(pair, nullptr, 16)));
    }
    return bytes;
}

std::vector<std::uint8_t> load_file(const std::string& path) {
    auto result = core::read_file(path);
    if (!result) {
        throw CliError(result.error().code, result.error().message);
    }
    return std::move(result.value());
}

void save_file(const std::string& path, const std::vector<std::uint8_t>& data) {
    if (path == "-") {
        std::fwrite(data.data(), 1, data.size(), stdout);
        return;
    }
    auto result = core::write_file(path, data.data(), data.size());
    if (!result) {
        throw CliError(result.error().code, result.error().message);
    }
}

std::string hex(std::uint64_t value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%llx",
                  static_cast<unsigned long long>(value));
    return buffer;
}

}  // namespace blook::kdu::cli
