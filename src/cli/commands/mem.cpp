// blook-kdu CLI: `mem` command group (physical / virtual / process memory).
//
// All option storage lives in a shared MemState so late-running CLI11 callbacks
// never reference destroyed locals.
#include <cstdio>
#include <memory>

#include "cli/commands.h"
#include "cli/output.h"

namespace blook::kdu::cli {
namespace {

struct MemState {
    std::string address;
    std::string size;
    std::string output;
    std::string bytes;
    std::string file;
    std::string pid;
};

void print_read_result(bool json, std::uint64_t address,
                       const std::vector<std::uint8_t>& bytes) {
    if (json) {
        std::printf("{\"address\":\"%s\",\"size\":%zu,\"hex\":\"",
                    hex(address).c_str(), bytes.size());
        for (auto byte : bytes) {
            std::printf("%02x", byte);
        }
        std::printf("\"}\n");
        return;
    }
    std::printf("%s", hexdump(bytes, address).c_str());
}

std::vector<std::uint8_t> input_bytes(const MemState& state) {
    if (state.file.empty() == state.bytes.empty()) {
        throw CliError(blook::kdu::Status::invalid_argument,
                       "provide either hex bytes or --file");
    }
    return !state.file.empty() ? load_file(state.file)
                               : parse_hex_bytes(state.bytes);
}

void add_read(CLI::App* group, Context& context, int kind,
              std::shared_ptr<MemState> state) {
    auto* read = group->add_subcommand("read", "Read memory");
    read->add_option("address", state->address, "Start address (hex or dec)")
        ->required();
    read->add_option("size", state->size, "Number of bytes")->required();
    read->add_option("-o,--output", state->output,
                     "Write raw bytes to this file");
    read->callback([&context, state, kind] {
        auto& session = context.ensure_session();
        const auto start = parse_u64(state->address);
        const auto count = parse_u64(state->size);
        auto result = kind == 0 ? session.read_physical_bytes(start, count)
                                : session.read_virtual_bytes(start, count);
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        if (!state->output.empty()) {
            save_file(state->output, result.value());
            std::printf("wrote %s to %s\n", human_size(result->size()).c_str(),
                        state->output.c_str());
            return;
        }
        print_read_result(context.options.json, start, result.value());
    });
}

void add_write(CLI::App* group, Context& context, int kind,
               std::shared_ptr<MemState> state) {
    auto* write = group->add_subcommand("write", "Write memory");
    write->add_option("address", state->address, "Start address")->required();
    write->add_option("-f,--file", state->file, "Read bytes from file");
    write->add_option("bytes", state->bytes, "Hex bytes, e.g. \"90 90\"");
    write->callback([&context, state, kind] {
        auto& session = context.ensure_session();
        const auto start = parse_u64(state->address);
        const auto bytes = input_bytes(*state);
        auto result =
            kind == 0
                ? session.write_physical(start, bytes.data(), bytes.size())
                : session.write_virtual(start, bytes.data(), bytes.size());
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        std::printf("wrote %zu bytes at %s\n", result.value(),
                    hex(start).c_str());
    });
}

void add_dump(CLI::App* group, Context& context, int kind,
              std::shared_ptr<MemState> state) {
    auto* dump = group->add_subcommand("dump", "Dump memory to a file");
    dump->add_option("address", state->address, "Start address")->required();
    dump->add_option("size", state->size, "Number of bytes")->required();
    dump->add_option("-o,--output", state->output, "Output file")->required();
    dump->callback([&context, state, kind] {
        auto& session = context.ensure_session();
        const auto start = parse_u64(state->address);
        const auto count = parse_u64(state->size);
        auto result = kind == 0 ? session.read_physical_bytes(start, count)
                                : session.read_virtual_bytes(start, count);
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        save_file(state->output, result.value());
        std::printf("dumped %s to %s\n", human_size(result->size()).c_str(),
                    state->output.c_str());
    });
}

}  // namespace

void add_mem_command(CLI::App& app, Context& context) {
    auto* mem = app.add_subcommand("mem", "Kernel memory access");
    mem->require_subcommand(1);
    auto state = std::make_shared<MemState>();

    for (int kind = 0; kind < 2; ++kind) {
        auto* group = mem->add_subcommand(
            kind == 0 ? "phys" : "virt",
            kind == 0 ? "Physical memory" : "Kernel virtual memory");
        group->require_subcommand(1);
        add_read(group, context, kind, state);
        add_write(group, context, kind, state);
        add_dump(group, context, kind, state);
    }

    auto* virt = mem->get_subcommand("virt");
    auto* translate = virt->add_subcommand("translate", "Translate VA -> PA");
    translate->add_option("address", state->address, "Virtual address")
        ->required();
    translate->callback([&context, state] {
        auto& session = context.ensure_session();
        const auto virtual_address = parse_u64(state->address);
        auto result = session.translate_virtual(virtual_address);
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        if (context.options.json) {
            std::printf("{\"virtual\":\"%s\",\"physical\":\"%s\"}\n",
                        hex(virtual_address).c_str(),
                        hex(result.value()).c_str());
        } else {
            std::printf("%s -> %s\n", hex(virtual_address).c_str(),
                        green(hex(result.value())).c_str());
        }
    });

    auto* process =
        mem->add_subcommand("process", "Process memory (CR3-based)");
    process->require_subcommand(1);
    process->add_option("--pid", state->pid, "Target PID")->required();

    auto* read = process->add_subcommand("read", "Read process memory");
    read->add_option("address", state->address, "Virtual address")->required();
    read->add_option("size", state->size, "Number of bytes")->required();
    read->add_option("-o,--output", state->output, "Write raw bytes to file");
    read->callback([&context, state] {
        auto& session = context.ensure_session();
        const auto process_id = parse_u32(state->pid);
        const auto start = parse_u64(state->address);
        const auto count = parse_u64(state->size);
        auto result = session.read_process_bytes(process_id, start, count);
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        if (!state->output.empty()) {
            save_file(state->output, result.value());
            std::printf("wrote %s to %s\n", human_size(result->size()).c_str(),
                        state->output.c_str());
            return;
        }
        print_read_result(context.options.json, start, result.value());
    });

    auto* write = process->add_subcommand("write", "Write process memory");
    write->add_option("address", state->address, "Virtual address")->required();
    write->add_option("-f,--file", state->file, "Read bytes from file");
    write->add_option("bytes", state->bytes, "Hex bytes");
    write->callback([&context, state] {
        auto& session = context.ensure_session();
        const auto process_id = parse_u32(state->pid);
        const auto start = parse_u64(state->address);
        const auto bytes = input_bytes(*state);
        auto result = session.write_process(process_id, start, bytes.data(),
                                            bytes.size());
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        std::printf("wrote %zu bytes at %s in pid %u\n", result.value(),
                    hex(start).c_str(), process_id);
    });

    auto* dump = process->add_subcommand("dump", "Dump process memory");
    dump->add_option("address", state->address, "Virtual address")->required();
    dump->add_option("size", state->size, "Number of bytes")->required();
    dump->add_option("-o,--output", state->output, "Output file")->required();
    dump->callback([&context, state] {
        auto& session = context.ensure_session();
        const auto process_id = parse_u32(state->pid);
        const auto start = parse_u64(state->address);
        const auto count = parse_u64(state->size);
        auto result = session.read_process_bytes(process_id, start, count);
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        save_file(state->output, result.value());
        std::printf("dumped %s to %s\n", human_size(result->size()).c_str(),
                    state->output.c_str());
    });

    auto* cr3 = process->add_subcommand("cr3", "Query process CR3");
    cr3->callback([&context, state] {
        auto& session = context.ensure_session();
        const auto process_id = parse_u32(state->pid);
        auto result = session.process_cr3(process_id);
        if (!result) {
            throw CliError(result.error().code, result.error().message);
        }
        if (context.options.json) {
            std::printf("{\"pid\":%u,\"cr3\":\"%s\"}\n", process_id,
                        hex(result.value()).c_str());
        } else {
            std::printf("pid %u CR3 %s\n", process_id,
                        green(hex(result.value())).c_str());
        }
    });
}

}  // namespace blook::kdu::cli
