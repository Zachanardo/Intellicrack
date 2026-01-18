#include "command_handler.h"

#include <sstream>
#include <vector>

#include "plugin.h"

namespace intellicrack {

namespace {

std::uint64_t parse_u64(const nlohmann::json& params, const char* key) {
    if (!params.contains(key)) {
        return 0;
    }
    const auto& value = params.at(key);
    if (value.is_number_integer()) {
        return value.get<std::uint64_t>();
    }
    if (value.is_number_unsigned()) {
        return value.get<std::uint64_t>();
    }
    if (value.is_string()) {
        const std::string text = value.get<std::string>();
        try {
            std::size_t idx = 0;
            std::uint64_t result = std::stoull(text, &idx, 0);
            if (idx > 0) {
                return result;
            }
        } catch (...) {
            return 0;
        }
    }
    return 0;
}

std::string to_hex_bytes(const std::vector<unsigned char>& bytes) {
    std::ostringstream oss;
    oss.setf(std::ios::hex, std::ios::basefield);
    oss.setf(std::ios::uppercase);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) {
            oss << ' ';
        }
        oss.width(2);
        oss.fill('0');
        oss << static_cast<int>(bytes[i]);
    }
    return oss.str();
}

}

nlohmann::json CommandHandler::handle(const nlohmann::json& request) const {
    if (!request.is_object()) {
        return build_error(request, "Invalid request");
    }

    const std::string command = request.value("command", "");
    const nlohmann::json params = request.value("params", nlohmann::json::object());

    if (command == "run") {
        return handle_run(request);
    }
    if (command == "pause") {
        return handle_pause(request);
    }
    if (command == "stop") {
        return handle_stop(request);
    }
    if (command == "step_into") {
        return handle_step(request, "StepInto");
    }
    if (command == "step_over") {
        return handle_step(request, "StepOver");
    }
    if (command == "step_out") {
        return handle_step(request, "StepOut");
    }
    if (command == "bp_set") {
        return handle_bp_set(request, params);
    }
    if (command == "bp_remove") {
        return handle_bp_remove(request, params);
    }
    if (command == "bp_list") {
        return handle_bp_list(request);
    }
    if (command == "wp_set") {
        return handle_wp_set(request, params);
    }
    if (command == "wp_remove") {
        return handle_wp_remove(request, params);
    }
    if (command == "wp_list") {
        return handle_wp_list(request);
    }
    if (command == "reg_all") {
        return handle_reg_all(request);
    }
    if (command == "reg_get") {
        return handle_reg_get(request, params);
    }
    if (command == "reg_set") {
        return handle_reg_set(request, params);
    }
    if (command == "disasm") {
        return handle_disasm(request, params);
    }
    if (command == "asm") {
        return handle_asm(request, params);
    }
    if (command == "exec") {
        return handle_exec(request, params);
    }

    return build_error(request, "Unknown command");
}

nlohmann::json CommandHandler::build_error(
    const nlohmann::json& request,
    const std::string& error) const {
    return {
        {"id", request.value("id", "")},
        {"type", "result"},
        {"success", false},
        {"error", error},
    };
}

nlohmann::json CommandHandler::build_success(
    const nlohmann::json& request,
    const nlohmann::json& data) const {
    return {
        {"id", request.value("id", "")},
        {"type", "result"},
        {"success", true},
        {"data", data},
    };
}

nlohmann::json CommandHandler::handle_exec(
    const nlohmann::json& request,
    const nlohmann::json& params) const {
    const std::string cmd = params.value("command", "");
    if (cmd.empty()) {
        return build_error(request, "Missing command");
    }
    if (!exec_cmd(cmd)) {
        return build_error(request, "Command execution failed");
    }
    return build_success(request, nlohmann::json{{"output", ""}});
}

nlohmann::json CommandHandler::handle_run(const nlohmann::json& request) const {
    if (!exec_cmd("run")) {
        return build_error(request, "Run failed");
    }
    return build_success(request, nlohmann::json::object());
}

nlohmann::json CommandHandler::handle_pause(const nlohmann::json& request) const {
    if (!exec_cmd("pause")) {
        return build_error(request, "Pause failed");
    }
    return build_success(request, nlohmann::json::object());
}

nlohmann::json CommandHandler::handle_stop(const nlohmann::json& request) const {
    if (!exec_cmd("stop")) {
        return build_error(request, "Stop failed");
    }
    return build_success(request, nlohmann::json::object());
}

nlohmann::json CommandHandler::handle_step(
    const nlohmann::json& request,
    const std::string& step_cmd) const {
    if (!exec_cmd(step_cmd)) {
        return build_error(request, "Step failed");
    }
    return build_success(request, nlohmann::json::object());
}

nlohmann::json CommandHandler::handle_bp_set(
    const nlohmann::json& request,
    const nlohmann::json& params) const {
    const std::uint64_t address = parse_u64(params, "address");
    const std::string type = params.value("type", "software");
    const std::string condition = params.value("condition", "");

    std::string cmd;
    if (type == "hardware") {
        cmd = "bph " + format_hex(address);
    } else if (type == "memory") {
        cmd = "bpm " + format_hex(address) + ", rw, 1";
    } else {
        cmd = "bp " + format_hex(address);
    }

    if (!exec_cmd(cmd)) {
        return build_error(request, "Failed to set breakpoint");
    }

    if (!condition.empty()) {
        exec_cmd("bpcond " + format_hex(address) + ", " + condition);
    }

    return build_success(request, nlohmann::json{{"address", address}});
}

nlohmann::json CommandHandler::handle_bp_remove(
    const nlohmann::json& request,
    const nlohmann::json& params) const {
    const std::uint64_t address = parse_u64(params, "address");
    if (!exec_cmd("bc " + format_hex(address))) {
        return build_error(request, "Failed to remove breakpoint");
    }
    return build_success(request, nlohmann::json::object());
}

nlohmann::json CommandHandler::handle_bp_list(const nlohmann::json& request) const {
    nlohmann::json entries = nlohmann::json::array();

    auto append_list = [&entries](BPXTYPE type, const std::string& type_name) {
        BRIDGE_BP_LIST list = {};
        if (!DbgGetBreakpointList(type, &list)) {
            return;
        }
        for (int i = 0; i < list.count; ++i) {
            const BRIDGE_BP& bp = list.bp[i];
            entries.push_back({
                {"address", static_cast<std::uint64_t>(bp.addr)},
                {"enabled", bp.enabled != 0},
                {"hit_count", static_cast<std::uint64_t>(bp.hitCount)},
                {"type", type_name},
            });
        }
        if (list.bp != nullptr) {
            BridgeFree(list.bp);
        }
    };

    append_list(bp_normal, "software");
    append_list(bp_hardware, "hardware");
    append_list(bp_memory, "memory");

    return build_success(request, entries);
}

nlohmann::json CommandHandler::handle_wp_set(
    const nlohmann::json& request,
    const nlohmann::json& params) const {
    const std::uint64_t address = parse_u64(params, "address");
    const std::uint64_t size = parse_u64(params, "size");
    const std::string access = params.value("access", "rw");

    std::ostringstream cmd;
    cmd << "bpm " << format_hex(address) << ", " << access << ", " << size;

    if (!exec_cmd(cmd.str())) {
        return build_error(request, "Failed to set watchpoint");
    }

    return build_success(request, nlohmann::json{{"address", address}});
}

nlohmann::json CommandHandler::handle_wp_remove(
    const nlohmann::json& request,
    const nlohmann::json& params) const {
    const std::uint64_t address = parse_u64(params, "address");
    if (!exec_cmd("bc " + format_hex(address))) {
        return build_error(request, "Failed to remove watchpoint");
    }
    return build_success(request, nlohmann::json::object());
}

nlohmann::json CommandHandler::handle_wp_list(const nlohmann::json& request) const {
    nlohmann::json entries = nlohmann::json::array();

    BRIDGE_BP_LIST list = {};
    if (DbgGetBreakpointList(bp_memory, &list)) {
        for (int i = 0; i < list.count; ++i) {
            const BRIDGE_BP& bp = list.bp[i];
            entries.push_back({
                {"address", static_cast<std::uint64_t>(bp.addr)},
                {"enabled", bp.enabled != 0},
                {"hit_count", static_cast<std::uint64_t>(bp.hitCount)},
                {"type", "memory"},
            });
        }
        if (list.bp != nullptr) {
            BridgeFree(list.bp);
        }
    }

    return build_success(request, entries);
}

nlohmann::json CommandHandler::handle_reg_all(const nlohmann::json& request) const {
    nlohmann::json regs = nlohmann::json::object();
    const std::vector<std::string> names = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "rflags", "cs", "ds", "es", "fs", "gs", "ss",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
        "eflags"
    };

    for (const auto& name : names) {
        duint value = 0;
        if (DbgValFromString(name.c_str(), &value)) {
            regs[name] = static_cast<std::uint64_t>(value);
        }
    }

    return build_success(request, regs);
}

nlohmann::json CommandHandler::handle_reg_get(
    const nlohmann::json& request,
    const nlohmann::json& params) const {
    const std::string reg = params.value("register", "");
    if (reg.empty()) {
        return build_error(request, "Missing register name");
    }
    duint value = 0;
    if (!DbgValFromString(reg.c_str(), &value)) {
        return build_error(request, "Register lookup failed");
    }
    return build_success(request, static_cast<std::uint64_t>(value));
}

nlohmann::json CommandHandler::handle_reg_set(
    const nlohmann::json& request,
    const nlohmann::json& params) const {
    const std::string reg = params.value("register", "");
    const std::uint64_t value = parse_u64(params, "value");
    if (reg.empty()) {
        return build_error(request, "Missing register name");
    }

    std::ostringstream cmd;
    cmd << reg << "=" << format_hex(value);
    if (!exec_cmd(cmd.str())) {
        return build_error(request, "Register set failed");
    }
    return build_success(request, nlohmann::json::object());
}

nlohmann::json CommandHandler::handle_disasm(
    const nlohmann::json& request,
    const nlohmann::json& params) const {
    const std::uint64_t start = parse_u64(params, "address");
    const std::uint64_t count = parse_u64(params, "count");
    const std::uint64_t max_count = count == 0 ? 10 : count;

    nlohmann::json lines = nlohmann::json::array();
    duint address = static_cast<duint>(start);

    for (std::uint64_t i = 0; i < max_count; ++i) {
        DISASM_INSTR instr = {};
        if (!DbgDisasmAt(address, &instr)) {
            break;
        }

        const std::uint64_t size = instr.size;
        if (size == 0) {
            break;
        }

        std::vector<unsigned char> bytes(static_cast<std::size_t>(size));
        if (!DbgMemRead(address, bytes.data(), static_cast<duint>(size))) {
            bytes.clear();
        }

        std::string text = instr.instruction;
        std::string mnemonic = text;
        std::string operands;
        std::size_t split = text.find(' ');
        if (split != std::string::npos) {
            mnemonic = text.substr(0, split);
            operands = text.substr(split + 1);
        }

        lines.push_back({
            {"address", static_cast<std::uint64_t>(address)},
            {"size", size},
            {"text", text},
            {"mnemonic", mnemonic},
            {"operands", operands},
            {"bytes", to_hex_bytes(bytes)},
        });

        address += static_cast<duint>(size);
    }

    return build_success(request, lines);
}

nlohmann::json CommandHandler::handle_asm(
    const nlohmann::json& request,
    const nlohmann::json& params) const {
    const std::uint64_t address = parse_u64(params, "address");
    const std::string instruction = params.value("instruction", "");
    if (instruction.empty()) {
        return build_error(request, "Missing instruction");
    }

    std::string mutable_instr = instruction;
    if (!DbgAssembleAt(static_cast<duint>(address), mutable_instr.data())) {
        return build_error(request, "Assembly failed");
    }

    DISASM_INSTR instr = {};
    if (!DbgDisasmAt(static_cast<duint>(address), &instr)) {
        return build_success(request, nlohmann::json::object());
    }

    const std::uint64_t size = instr.size;
    std::vector<unsigned char> bytes(static_cast<std::size_t>(size));
    if (!DbgMemRead(static_cast<duint>(address), bytes.data(), static_cast<duint>(size))) {
        bytes.clear();
    }

    return build_success(request, nlohmann::json{{"bytes", to_hex_bytes(bytes)}, {"size", size}});
}

bool CommandHandler::exec_cmd(const std::string& cmd) {
    return DbgCmdExecDirect(cmd.c_str()) ? true : false;
}

std::string CommandHandler::format_hex(std::uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << value;
    return oss.str();
}

}
