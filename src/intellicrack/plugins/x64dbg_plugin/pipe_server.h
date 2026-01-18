#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include <windows.h>

#include "third_party/nlohmann/json.hpp"

namespace intellicrack {

class PipeServer {
public:
    using Handler = std::function<nlohmann::json(const nlohmann::json&)>;

    explicit PipeServer(Handler handler);
    ~PipeServer();

    bool start();
    void stop();
    void send_event(const nlohmann::json& event);

private:
    void run();
    bool read_message(HANDLE pipe, std::string& out);
    bool write_message(HANDLE pipe, const std::string& data);
    bool write_payload(HANDLE pipe, const void* data, std::size_t size);
    bool read_payload(HANDLE pipe, void* buffer, std::size_t size);
    std::string serialize(const nlohmann::json& payload) const;

    std::atomic<bool> running_;
    std::thread worker_;
    std::mutex write_mutex_;
    std::mutex handle_mutex_;
    HANDLE pipe_handle_;
    Handler handler_;
};

}
