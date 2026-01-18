#pragma once

#include <string>

#include "third_party/nlohmann/json.hpp"

namespace intellicrack {

class CommandHandler {
public:
    nlohmann::json handle(const nlohmann::json& request) const;

private:
    nlohmann::json build_error(const nlohmann::json& request, const std::string& error) const;
    nlohmann::json build_success(const nlohmann::json& request, const nlohmann::json& data) const;
    nlohmann::json handle_exec(const nlohmann::json& request, const nlohmann::json& params) const;
    nlohmann::json handle_run(const nlohmann::json& request) const;
    nlohmann::json handle_pause(const nlohmann::json& request) const;
    nlohmann::json handle_stop(const nlohmann::json& request) const;
    nlohmann::json handle_step(const nlohmann::json& request, const std::string& step_cmd) const;
    nlohmann::json handle_bp_set(const nlohmann::json& request, const nlohmann::json& params) const;
    nlohmann::json handle_bp_remove(const nlohmann::json& request, const nlohmann::json& params) const;
    nlohmann::json handle_bp_list(const nlohmann::json& request) const;
    nlohmann::json handle_wp_set(const nlohmann::json& request, const nlohmann::json& params) const;
    nlohmann::json handle_wp_remove(const nlohmann::json& request, const nlohmann::json& params) const;
    nlohmann::json handle_wp_list(const nlohmann::json& request) const;
    nlohmann::json handle_reg_all(const nlohmann::json& request) const;
    nlohmann::json handle_reg_get(const nlohmann::json& request, const nlohmann::json& params) const;
    nlohmann::json handle_reg_set(const nlohmann::json& request, const nlohmann::json& params) const;
    nlohmann::json handle_disasm(const nlohmann::json& request, const nlohmann::json& params) const;
    nlohmann::json handle_asm(const nlohmann::json& request, const nlohmann::json& params) const;

    static bool exec_cmd(const std::string& cmd);
    static std::string format_hex(std::uint64_t value);
};

}
