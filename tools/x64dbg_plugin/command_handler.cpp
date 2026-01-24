/**
 * @file command_handler.cpp
 * @brief Command dispatcher implementation for Intellicrack bridge
 */

#include "command_handler.h"
#include "intellicrack_bridge.h"

#include <pluginsdk/_plugins.h>
#include <pluginsdk/_scriptapi_memory.h>
#include <pluginsdk/_scriptapi_register.h>
#include <pluginsdk/_scriptapi_debug.h>
#include <pluginsdk/_scriptapi_module.h>
#include <pluginsdk/_scriptapi_misc.h>
#include <pluginsdk/bridgemain.h>

#include <cstdio>
#include <cstring>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>

namespace intellicrack {

CommandHandler g_command_handler;

CommandHandler::CommandHandler() {
    register_commands();
}

void CommandHandler::register_commands() {
    m_commands["exec"] = [this](const PipeMessage& m) { return cmd_exec(m); };
    m_commands["run"] = [this](const PipeMessage& m) { return cmd_run(m); };
    m_commands["pause"] = [this](const PipeMessage& m) { return cmd_pause(m); };
    m_commands["stop"] = [this](const PipeMessage& m) { return cmd_stop(m); };
    m_commands["step_into"] = [this](const PipeMessage& m) { return cmd_step_into(m); };
    m_commands["step_over"] = [this](const PipeMessage& m) { return cmd_step_over(m); };
    m_commands["step_out"] = [this](const PipeMessage& m) { return cmd_step_out(m); };
    m_commands["run_to"] = [this](const PipeMessage& m) { return cmd_run_to(m); };

    m_commands["bp_set"] = [this](const PipeMessage& m) { return cmd_bp_set(m); };
    m_commands["bp_remove"] = [this](const PipeMessage& m) { return cmd_bp_remove(m); };
    m_commands["bp_list"] = [this](const PipeMessage& m) { return cmd_bp_list(m); };
    m_commands["bp_enable"] = [this](const PipeMessage& m) { return cmd_bp_enable(m); };
    m_commands["bp_disable"] = [this](const PipeMessage& m) { return cmd_bp_disable(m); };

    m_commands["wp_set"] = [this](const PipeMessage& m) { return cmd_wp_set(m); };
    m_commands["wp_remove"] = [this](const PipeMessage& m) { return cmd_wp_remove(m); };
    m_commands["wp_list"] = [this](const PipeMessage& m) { return cmd_wp_list(m); };

    m_commands["reg_all"] = [this](const PipeMessage& m) { return cmd_reg_all(m); };
    m_commands["reg_get"] = [this](const PipeMessage& m) { return cmd_reg_get(m); };
    m_commands["reg_set"] = [this](const PipeMessage& m) { return cmd_reg_set(m); };

    m_commands["mem_read"] = [this](const PipeMessage& m) { return cmd_mem_read(m); };
    m_commands["mem_write"] = [this](const PipeMessage& m) { return cmd_mem_write(m); };
    m_commands["mem_map"] = [this](const PipeMessage& m) { return cmd_mem_map(m); };

    m_commands["mod_list"] = [this](const PipeMessage& m) { return cmd_mod_list(m); };
    m_commands["mod_base"] = [this](const PipeMessage& m) { return cmd_mod_base(m); };
    m_commands["mod_exports"] = [this](const PipeMessage& m) { return cmd_mod_exports(m); };
    m_commands["mod_imports"] = [this](const PipeMessage& m) { return cmd_mod_imports(m); };

    m_commands["disasm"] = [this](const PipeMessage& m) { return cmd_disasm(m); };
    m_commands["assemble"] = [this](const PipeMessage& m) { return cmd_assemble(m); };

    m_commands["goto"] = [this](const PipeMessage& m) { return cmd_goto(m); };
    m_commands["status"] = [this](const PipeMessage& m) { return cmd_status(m); };
    m_commands["ping"] = [this](const PipeMessage& m) { return cmd_ping(m); };
}

PipeResponse CommandHandler::handle_command(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;
    response.success = false;

    auto it = m_commands.find(msg.command);
    if (it != m_commands.end()) {
        return it->second(msg);
    }

    response.error = "Unknown command: " + msg.command;
    return response;
}

PipeResponse CommandHandler::cmd_exec(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t cmd_pos = msg.params.find("\"cmd\"");
    if (cmd_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'cmd' parameter";
        return response;
    }

    size_t start = msg.params.find('"', cmd_pos + 5);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);

    if (start == std::string::npos || end == std::string::npos) {
        response.success = false;
        response.error = "Invalid 'cmd' parameter format";
        return response;
    }

    std::string cmd = msg.params.substr(start, end - start);

    bool result = DbgCmdExec(cmd.c_str());
    response.success = result;
    if (result) {
        response.result = "true";
    } else {
        response.error = "Command execution failed";
    }

    return response;
}

PipeResponse CommandHandler::cmd_run(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    DbgCmdExec("run");
    g_state.paused = false;

    response.success = true;
    response.result = "true";
    return response;
}

PipeResponse CommandHandler::cmd_pause(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    DbgCmdExec("pause");
    g_state.paused = true;

    response.success = true;
    response.result = "true";
    return response;
}

PipeResponse CommandHandler::cmd_stop(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    DbgCmdExec("stop");
    g_state.debugging = false;
    g_state.paused = false;

    response.success = true;
    response.result = "true";
    return response;
}

PipeResponse CommandHandler::cmd_step_into(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    DbgCmdExec("sti");

    response.success = true;
    response.result = "true";
    return response;
}

PipeResponse CommandHandler::cmd_step_over(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    DbgCmdExec("sto");

    response.success = true;
    response.result = "true";
    return response;
}

PipeResponse CommandHandler::cmd_step_out(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    DbgCmdExec("rtr");

    response.success = true;
    response.result = "true";
    return response;
}

PipeResponse CommandHandler::cmd_run_to(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);

    if (start == std::string::npos || end == std::string::npos) {
        response.success = false;
        response.error = "Invalid 'address' parameter";
        return response;
    }

    std::string addr_str = msg.params.substr(start, end - start);
    uint64_t address = parse_address(addr_str);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "bp %s, ss", addr_str.c_str());
    DbgCmdExec(cmd);
    DbgCmdExec("run");

    response.success = true;
    response.result = format_address(address);
    return response;
}

PipeResponse CommandHandler::cmd_bp_set(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);

    if (start == std::string::npos || end == std::string::npos) {
        response.success = false;
        response.error = "Invalid 'address' parameter";
        return response;
    }

    std::string addr_str = msg.params.substr(start, end - start);
    uint64_t address = parse_address(addr_str);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "bp %s", addr_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    if (result) {
        response.result = "\"" + format_address(address) + "\"";
    } else {
        response.error = "Failed to set breakpoint";
    }
    return response;
}

PipeResponse CommandHandler::cmd_bp_remove(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);

    if (start == std::string::npos || end == std::string::npos) {
        response.success = false;
        response.error = "Invalid 'address' parameter";
        return response;
    }

    std::string addr_str = msg.params.substr(start, end - start);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "bc %s", addr_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_bp_list(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    BPMAP bpmap;
    if (!DbgGetBpList(bp_normal, &bpmap)) {
        response.success = false;
        response.error = "Failed to get breakpoint list";
        return response;
    }

    std::ostringstream ss;
    ss << "[";

    for (int i = 0; i < bpmap.count; i++) {
        if (i > 0) ss << ",";
        ss << "{\"address\":\"" << format_address(bpmap.bp[i].addr) << "\","
           << "\"enabled\":" << (bpmap.bp[i].enabled ? "true" : "false") << ","
           << "\"type\":\"normal\""
           << "}";
    }

    ss << "]";

    if (bpmap.bp) {
        BridgeFree(bpmap.bp);
    }

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_bp_enable(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);

    std::string addr_str = msg.params.substr(start, end - start);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "be %s", addr_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_bp_disable(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);

    std::string addr_str = msg.params.substr(start, end - start);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "bd %s", addr_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_wp_set(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    size_t size_pos = msg.params.find("\"size\"");
    size_t type_pos = msg.params.find("\"type\"");

    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);

    std::string wp_type = "rw";
    if (type_pos != std::string::npos) {
        start = msg.params.find('"', type_pos + 6);
        if (start != std::string::npos) start++;
        end = msg.params.find('"', start);
        if (end != std::string::npos) {
            wp_type = msg.params.substr(start, end - start);
        }
    }

    int size = 4;
    if (size_pos != std::string::npos) {
        start = size_pos + 6;
        while (start < msg.params.length() && !isdigit(msg.params[start])) start++;
        end = start;
        while (end < msg.params.length() && isdigit(msg.params[end])) end++;
        if (end > start) {
            size = std::stoi(msg.params.substr(start, end - start));
        }
    }

    char cmd[128];
    if (wp_type == "r" || wp_type == "read") {
        snprintf(cmd, sizeof(cmd), "bphws %s, r, %d", addr_str.c_str(), size);
    } else if (wp_type == "w" || wp_type == "write") {
        snprintf(cmd, sizeof(cmd), "bphws %s, w, %d", addr_str.c_str(), size);
    } else {
        snprintf(cmd, sizeof(cmd), "bphws %s, rw, %d", addr_str.c_str(), size);
    }

    bool result = DbgCmdExec(cmd);
    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_wp_remove(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "bphwc %s", addr_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_wp_list(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    BPMAP bpmap;
    if (!DbgGetBpList(bp_hardware, &bpmap)) {
        response.success = false;
        response.error = "Failed to get watchpoint list";
        return response;
    }

    std::ostringstream ss;
    ss << "[";

    for (int i = 0; i < bpmap.count; i++) {
        if (i > 0) ss << ",";
        ss << "{\"address\":\"" << format_address(bpmap.bp[i].addr) << "\","
           << "\"enabled\":" << (bpmap.bp[i].enabled ? "true" : "false") << ","
           << "\"type\":\"hardware\""
           << "}";
    }

    ss << "]";

    if (bpmap.bp) {
        BridgeFree(bpmap.bp);
    }

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_reg_all(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    REGDUMP regdump;
    if (!DbgGetRegDumpEx(&regdump, sizeof(regdump))) {
        response.success = false;
        response.error = "Failed to get register dump";
        return response;
    }

    std::ostringstream ss;
    ss << "{";

#ifdef BUILD_X64
    ss << "\"rax\":\"" << format_address(regdump.regcontext.cax) << "\",";
    ss << "\"rbx\":\"" << format_address(regdump.regcontext.cbx) << "\",";
    ss << "\"rcx\":\"" << format_address(regdump.regcontext.ccx) << "\",";
    ss << "\"rdx\":\"" << format_address(regdump.regcontext.cdx) << "\",";
    ss << "\"rsi\":\"" << format_address(regdump.regcontext.csi) << "\",";
    ss << "\"rdi\":\"" << format_address(regdump.regcontext.cdi) << "\",";
    ss << "\"rbp\":\"" << format_address(regdump.regcontext.cbp) << "\",";
    ss << "\"rsp\":\"" << format_address(regdump.regcontext.csp) << "\",";
    ss << "\"rip\":\"" << format_address(regdump.regcontext.cip) << "\",";
    ss << "\"r8\":\"" << format_address(regdump.regcontext.r8) << "\",";
    ss << "\"r9\":\"" << format_address(regdump.regcontext.r9) << "\",";
    ss << "\"r10\":\"" << format_address(regdump.regcontext.r10) << "\",";
    ss << "\"r11\":\"" << format_address(regdump.regcontext.r11) << "\",";
    ss << "\"r12\":\"" << format_address(regdump.regcontext.r12) << "\",";
    ss << "\"r13\":\"" << format_address(regdump.regcontext.r13) << "\",";
    ss << "\"r14\":\"" << format_address(regdump.regcontext.r14) << "\",";
    ss << "\"r15\":\"" << format_address(regdump.regcontext.r15) << "\",";
#else
    ss << "\"eax\":\"" << format_address(regdump.regcontext.cax) << "\",";
    ss << "\"ebx\":\"" << format_address(regdump.regcontext.cbx) << "\",";
    ss << "\"ecx\":\"" << format_address(regdump.regcontext.ccx) << "\",";
    ss << "\"edx\":\"" << format_address(regdump.regcontext.cdx) << "\",";
    ss << "\"esi\":\"" << format_address(regdump.regcontext.csi) << "\",";
    ss << "\"edi\":\"" << format_address(regdump.regcontext.cdi) << "\",";
    ss << "\"ebp\":\"" << format_address(regdump.regcontext.cbp) << "\",";
    ss << "\"esp\":\"" << format_address(regdump.regcontext.csp) << "\",";
    ss << "\"eip\":\"" << format_address(regdump.regcontext.cip) << "\",";
#endif

    ss << "\"eflags\":\"" << format_address(regdump.regcontext.eflags) << "\"";
    ss << "}";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_reg_get(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t name_pos = msg.params.find("\"name\"");
    if (name_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'name' parameter";
        return response;
    }

    size_t start = msg.params.find('"', name_pos + 6);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string reg_name = msg.params.substr(start, end - start);

    duint value = DbgValFromString(reg_name.c_str());

    response.success = true;
    response.result = "\"" + format_address(value) + "\"";
    return response;
}

PipeResponse CommandHandler::cmd_reg_set(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t name_pos = msg.params.find("\"name\"");
    size_t value_pos = msg.params.find("\"value\"");

    if (name_pos == std::string::npos || value_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'name' or 'value' parameter";
        return response;
    }

    size_t start = msg.params.find('"', name_pos + 6);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string reg_name = msg.params.substr(start, end - start);

    start = msg.params.find('"', value_pos + 7);
    if (start != std::string::npos) start++;
    end = msg.params.find('"', start);
    std::string value_str = msg.params.substr(start, end - start);

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "mov %s, %s", reg_name.c_str(), value_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_mem_read(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    size_t size_pos = msg.params.find("\"size\"");

    if (addr_pos == std::string::npos || size_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' or 'size' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);
    uint64_t address = parse_address(addr_str);

    start = size_pos + 6;
    while (start < msg.params.length() && !isdigit(msg.params[start])) start++;
    end = start;
    while (end < msg.params.length() && isdigit(msg.params[end])) end++;
    int size = std::stoi(msg.params.substr(start, end - start));

    if (size <= 0 || size > 65536) {
        response.success = false;
        response.error = "Invalid size parameter";
        return response;
    }

    std::vector<uint8_t> buffer(size);
    if (!DbgMemRead(static_cast<duint>(address), buffer.data(), size)) {
        response.success = false;
        response.error = "Failed to read memory";
        return response;
    }

    std::ostringstream ss;
    ss << "\"";
    for (int i = 0; i < size; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(buffer[i]);
    }
    ss << "\"";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_mem_write(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    size_t data_pos = msg.params.find("\"data\"");

    if (addr_pos == std::string::npos || data_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' or 'data' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);
    uint64_t address = parse_address(addr_str);

    start = msg.params.find('"', data_pos + 6);
    if (start != std::string::npos) start++;
    end = msg.params.find('"', start);
    std::string hex_data = msg.params.substr(start, end - start);

    std::vector<uint8_t> data;
    for (size_t i = 0; i + 1 < hex_data.length(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex_data.substr(i, 2), nullptr, 16));
        data.push_back(byte);
    }

    if (data.empty()) {
        response.success = false;
        response.error = "No data to write";
        return response;
    }

    bool result = DbgMemWrite(static_cast<duint>(address), data.data(), data.size());

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_mem_map(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    MEMMAP memmap;
    if (!DbgMemMap(&memmap)) {
        response.success = false;
        response.error = "Failed to get memory map";
        return response;
    }

    std::ostringstream ss;
    ss << "[";

    for (int i = 0; i < memmap.count; i++) {
        if (i > 0) ss << ",";
        ss << "{";
        ss << "\"base\":\"" << format_address(memmap.page[i].mbi.BaseAddress) << "\",";
        ss << "\"size\":" << memmap.page[i].mbi.RegionSize << ",";
        ss << "\"protect\":" << memmap.page[i].mbi.Protect << ",";
        ss << "\"type\":" << memmap.page[i].mbi.Type;
        ss << "}";
    }

    ss << "]";

    if (memmap.page) {
        BridgeFree(memmap.page);
    }

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_mod_list(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    BridgeList<Script::Module::ModuleInfo> modules;
    Script::Module::GetList(&modules);

    std::ostringstream ss;
    ss << "[";

    for (int i = 0; i < modules.Count(); i++) {
        if (i > 0) ss << ",";
        ss << "{";
        ss << "\"name\":\"" << escape_json(modules[i].name) << "\",";
        ss << "\"path\":\"" << escape_json(modules[i].path) << "\",";
        ss << "\"base\":\"" << format_address(modules[i].base) << "\",";
        ss << "\"size\":" << modules[i].size << ",";
        ss << "\"entry\":\"" << format_address(modules[i].entry) << "\"";
        ss << "}";
    }

    ss << "]";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_mod_base(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t name_pos = msg.params.find("\"name\"");
    if (name_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'name' parameter";
        return response;
    }

    size_t start = msg.params.find('"', name_pos + 6);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string mod_name = msg.params.substr(start, end - start);

    duint base = Script::Module::BaseFromName(mod_name.c_str());

    response.success = base != 0;
    if (base) {
        response.result = "\"" + format_address(base) + "\"";
    } else {
        response.error = "Module not found";
    }
    return response;
}

PipeResponse CommandHandler::cmd_mod_exports(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t name_pos = msg.params.find("\"name\"");
    if (name_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'name' parameter";
        return response;
    }

    size_t start = msg.params.find('"', name_pos + 6);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string mod_name = msg.params.substr(start, end - start);

    duint base = Script::Module::BaseFromName(mod_name.c_str());
    if (!base) {
        response.success = false;
        response.error = "Module not found";
        return response;
    }

    ListInfo export_list = {};
    if (!Script::Module::GetExports(&export_list, base)) {
        response.success = true;
        response.result = "[]";
        return response;
    }

    std::ostringstream ss;
    ss << "[";

    auto* exports = static_cast<Script::Module::ModuleExport*>(export_list.data);
    for (int i = 0; i < export_list.count; i++) {
        if (i > 0) ss << ",";
        ss << "{";
        ss << "\"ordinal\":" << exports[i].ordinal << ",";
        ss << "\"rva\":\"" << format_address(exports[i].rva) << "\",";
        ss << "\"va\":\"" << format_address(exports[i].va) << "\",";
        ss << "\"forwarded\":" << (exports[i].forwarded ? "true" : "false") << ",";
        ss << "\"forwardName\":\"" << escape_json(exports[i].forwardName) << "\",";
        ss << "\"name\":\"" << escape_json(exports[i].name) << "\",";
        ss << "\"undecoratedName\":\"" << escape_json(exports[i].undecoratedName) << "\"";
        ss << "}";
    }

    ss << "]";

    if (export_list.data) {
        BridgeFree(export_list.data);
    }

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_mod_imports(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t name_pos = msg.params.find("\"name\"");
    if (name_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'name' parameter";
        return response;
    }

    size_t start = msg.params.find('"', name_pos + 6);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string mod_name = msg.params.substr(start, end - start);

    duint base = Script::Module::BaseFromName(mod_name.c_str());
    if (!base) {
        response.success = false;
        response.error = "Module not found";
        return response;
    }

    ListInfo import_list = {};
    if (!Script::Module::GetImports(&import_list, base)) {
        response.success = true;
        response.result = "[]";
        return response;
    }

    std::ostringstream ss;
    ss << "[";

    auto* imports = static_cast<Script::Module::ModuleImport*>(import_list.data);
    for (int i = 0; i < import_list.count; i++) {
        if (i > 0) ss << ",";
        ss << "{";
        ss << "\"iatRva\":\"" << format_address(imports[i].iatRva) << "\",";
        ss << "\"iatVa\":\"" << format_address(imports[i].iatVa) << "\",";
        ss << "\"ordinal\":" << imports[i].ordinal << ",";
        ss << "\"name\":\"" << escape_json(imports[i].name) << "\",";
        ss << "\"undecoratedName\":\"" << escape_json(imports[i].undecoratedName) << "\"";
        ss << "}";
    }

    ss << "]";

    if (import_list.data) {
        BridgeFree(import_list.data);
    }

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_disasm(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    size_t count_pos = msg.params.find("\"count\"");

    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);
    uint64_t address = parse_address(addr_str);

    int count = 10;
    if (count_pos != std::string::npos) {
        start = count_pos + 7;
        while (start < msg.params.length() && !isdigit(msg.params[start])) start++;
        end = start;
        while (end < msg.params.length() && isdigit(msg.params[end])) end++;
        if (end > start) {
            count = std::stoi(msg.params.substr(start, end - start));
        }
    }

    std::ostringstream ss;
    ss << "[";

    duint current = static_cast<duint>(address);
    for (int i = 0; i < count; i++) {
        DISASM_INSTR instr;
        if (!DbgDisasmAt(current, &instr)) {
            break;
        }

        if (i > 0) ss << ",";
        ss << "{";
        ss << "\"address\":\"" << format_address(current) << "\",";
        ss << "\"instruction\":\"" << escape_json(instr.instruction) << "\",";
        ss << "\"size\":" << instr.instr_size;
        ss << "}";

        current += instr.instr_size;
    }

    ss << "]";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_assemble(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    size_t instr_pos = msg.params.find("\"instruction\"");

    if (addr_pos == std::string::npos || instr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' or 'instruction' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);

    start = msg.params.find('"', instr_pos + 13);
    if (start != std::string::npos) start++;
    end = msg.params.find('"', start);
    std::string instruction = msg.params.substr(start, end - start);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "asm %s, \"%s\"", addr_str.c_str(), instruction.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_goto(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    size_t addr_pos = msg.params.find("\"address\"");
    if (addr_pos == std::string::npos) {
        response.success = false;
        response.error = "Missing 'address' parameter";
        return response;
    }

    size_t start = msg.params.find('"', addr_pos + 9);
    if (start != std::string::npos) start++;
    size_t end = msg.params.find('"', start);
    std::string addr_str = msg.params.substr(start, end - start);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "disasm %s", addr_str.c_str());
    bool result = DbgCmdExec(cmd);

    response.success = result;
    response.result = result ? "true" : "false";
    return response;
}

PipeResponse CommandHandler::cmd_status(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;

    std::ostringstream ss;
    ss << "{";
    ss << "\"debugging\":" << (g_state.debugging ? "true" : "false") << ",";
    ss << "\"paused\":" << (g_state.paused ? "true" : "false") << ",";
    ss << "\"initialized\":" << (g_state.initialized ? "true" : "false");
    ss << "}";

    response.success = true;
    response.result = ss.str();
    return response;
}

PipeResponse CommandHandler::cmd_ping(const PipeMessage& msg) {
    PipeResponse response;
    response.id = msg.id;
    response.success = true;
    response.result = "\"pong\"";
    return response;
}

uint64_t CommandHandler::parse_address(const std::string& addr_str) {
    if (addr_str.empty()) return 0;

    std::string clean = addr_str;
    if (clean.substr(0, 2) == "0x" || clean.substr(0, 2) == "0X") {
        clean = clean.substr(2);
    }

    return std::stoull(clean, nullptr, 16);
}

std::string CommandHandler::format_address(uint64_t addr) {
    char buffer[32];
#ifdef BUILD_X64
    snprintf(buffer, sizeof(buffer), "0x%016llX", static_cast<unsigned long long>(addr));
#else
    snprintf(buffer, sizeof(buffer), "0x%08X", static_cast<unsigned int>(addr));
#endif
    return std::string(buffer);
}

std::string CommandHandler::escape_json(const std::string& s) {
    std::ostringstream ss;
    for (char c : s) {
        switch (c) {
            case '"': ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    ss << "\\u" << std::hex << std::setfill('0') << std::setw(4) << static_cast<int>(c);
                } else {
                    ss << c;
                }
        }
    }
    return ss.str();
}

}
