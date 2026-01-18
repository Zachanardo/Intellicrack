#include "event_handler.h"

#include <rpc.h>

#include "pipe_server.h"

namespace intellicrack {

EventHandler::EventHandler() : server_(nullptr) {}

void EventHandler::set_server(PipeServer* server) {
    server_ = server;
}

static std::string new_uuid() {
    UUID uuid = {};
    if (UuidCreate(&uuid) != RPC_S_OK) {
        return "";
    }

    RPC_CSTR buffer = nullptr;
    if (UuidToStringA(&uuid, &buffer) != RPC_S_OK || buffer == nullptr) {
        return "";
    }

    std::string result(reinterpret_cast<const char*>(buffer));
    RpcStringFreeA(&buffer);
    return result;
}

void EventHandler::send_event(const std::string& name, std::uint64_t address) {
    if (server_ == nullptr) {
        return;
    }
    nlohmann::json payload = {
        {"id", new_uuid()},
        {"type", "event"},
        {"event", name},
        {"address", address},
    };
    server_->send_event(payload);
}

void EventHandler::send_breakpoint(std::uint64_t address) {
    send_event("breakpoint", address);
}

void EventHandler::send_watchpoint(std::uint64_t address) {
    send_event("watchpoint", address);
}

}
