// blook-kdu CLI: shared context and helpers.
#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "blook/kdu/kdu.h"

namespace blook::kdu::cli {

// Global command-line options (also feed the SDK OpenOptions).
struct GlobalOptions {
    bool json = false;
    bool verbose = false;
    bool color = true;
    std::string exploit;
    bool use_payload = true;
    bool driver_only = false;
    bool keep_dse = false;
    std::string log_level = "warn";
    std::uint32_t timeout_ms = 5000;
};

// Thrown by command handlers; main() turns it into a message + exit code.
class CliError : public std::runtime_error {
   public:
    CliError(blook::kdu::Status status, std::string message)
        : std::runtime_error(std::move(message)), status_(status) {}
    [[nodiscard]] blook::kdu::Status status() const noexcept { return status_; }

   private:
    blook::kdu::Status status_;
};

struct Context {
    GlobalOptions options;
    std::optional<blook::kdu::Session> session;

    // Open (once) and return the SDK session. Throws CliError on failure.
    blook::kdu::Session& ensure_session();
    // Close the session if open (used by the auto-cleanup path).
    void close_session();
};

// Parse "0x1234" / "4660" / "1234h".
std::uint64_t parse_u64(std::string_view text);
std::uint32_t parse_u32(std::string_view text);

// Parse "de ad be ef" hex bytes (also accepts "deadbeef").
std::vector<std::uint8_t> parse_hex_bytes(std::string_view text);

// Load bytes from a file, or single path; throws CliError.
std::vector<std::uint8_t> load_file(const std::string& path);

// Write bytes to a file (or "-" for stdout).
void save_file(const std::string& path, const std::vector<std::uint8_t>& data);

// Human readable address formatting.
std::string hex(std::uint64_t value);

}  // namespace blook::kdu::cli
