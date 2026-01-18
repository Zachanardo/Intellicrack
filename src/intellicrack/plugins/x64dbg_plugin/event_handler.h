#pragma once

#include <cstdint>
#include <string>

#include "third_party/nlohmann/json.hpp"

namespace intellicrack {

class PipeServer;

class EventHandler {
public:
    EventHandler();
    void set_server(PipeServer* server);
    void send_breakpoint(std::uint64_t address);
    void send_watchpoint(std::uint64_t address);

private:
    void send_event(const std::string& name, std::uint64_t address);

    PipeServer* server_;
};

}
