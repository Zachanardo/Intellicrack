#include "pipe_server.h"

#include <chrono>
#include <vector>

#include "protocol.h"

namespace intellicrack {

PipeServer::PipeServer(Handler handler)
    : running_(false),
      pipe_handle_(INVALID_HANDLE_VALUE),
      handler_(std::move(handler)) {}

PipeServer::~PipeServer() {
    stop();
}

bool PipeServer::start() {
    if (running_) {
        return true;
    }
    running_ = true;
    worker_ = std::thread(&PipeServer::run, this);
    return true;
}

void PipeServer::stop() {
    if (!running_) {
        return;
    }
    running_ = false;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> guard(handle_mutex_);
        pipe = pipe_handle_;
    }
    if (pipe != INVALID_HANDLE_VALUE) {
        CancelIoEx(pipe, nullptr);
    }
    if (worker_.joinable()) {
        worker_.join();
    }
}

void PipeServer::send_event(const nlohmann::json& event) {
    std::string payload = serialize(event);
    std::lock_guard<std::mutex> guard(write_mutex_);
    HANDLE pipe = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> handle_guard(handle_mutex_);
        pipe = pipe_handle_;
    }
    if (pipe == INVALID_HANDLE_VALUE) {
        return;
    }
    write_message(pipe, payload);
}

void PipeServer::run() {
    while (running_) {
        HANDLE pipe = CreateNamedPipeW(
            kPipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            kMaxMessageSize,
            kMaxMessageSize,
            0,
            nullptr);

        if (pipe == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        BOOL connected = ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) {
            CloseHandle(pipe);
            continue;
        }

        {
            std::lock_guard<std::mutex> guard(handle_mutex_);
            pipe_handle_ = pipe;
        }

        while (running_) {
            std::string request_data;
            if (!read_message(pipe, request_data)) {
                break;
            }

            nlohmann::json response;
            try {
                nlohmann::json request = nlohmann::json::parse(request_data);
                response = handler_(request);
            } catch (const std::exception& exc) {
                response = {
                    {"id", ""},
                    {"type", "result"},
                    {"success", false},
                    {"error", exc.what()},
                };
            }

            std::string response_data = serialize(response);
            if (!write_message(pipe, response_data)) {
                break;
            }
        }

        {
            std::lock_guard<std::mutex> guard(handle_mutex_);
            pipe_handle_ = INVALID_HANDLE_VALUE;
        }

        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
}

bool PipeServer::read_message(HANDLE pipe, std::string& out) {
    std::uint32_t length = 0;
    if (!read_payload(pipe, &length, sizeof(length))) {
        return false;
    }
    if (length == 0 || length > kMaxMessageSize) {
        return false;
    }

    std::vector<char> buffer(length);
    if (!read_payload(pipe, buffer.data(), length)) {
        return false;
    }

    out.assign(buffer.begin(), buffer.end());
    return true;
}

bool PipeServer::write_message(HANDLE pipe, const std::string& data) {
    std::uint32_t length = static_cast<std::uint32_t>(data.size());
    if (length == 0 || length > kMaxMessageSize) {
        return false;
    }
    if (!write_payload(pipe, &length, sizeof(length))) {
        return false;
    }
    return write_payload(pipe, data.data(), data.size());
}

bool PipeServer::write_payload(HANDLE pipe, const void* data, std::size_t size) {
    const std::uint8_t* ptr = static_cast<const std::uint8_t*>(data);
    std::size_t remaining = size;

    while (remaining > 0) {
        DWORD written = 0;
        DWORD chunk = remaining > 65536 ? 65536 : static_cast<DWORD>(remaining);
        BOOL ok = WriteFile(pipe, ptr, chunk, &written, nullptr);
        if (!ok || written == 0) {
            return false;
        }
        ptr += written;
        remaining -= written;
    }
    return true;
}

bool PipeServer::read_payload(HANDLE pipe, void* buffer, std::size_t size) {
    std::uint8_t* ptr = static_cast<std::uint8_t*>(buffer);
    std::size_t remaining = size;

    while (remaining > 0) {
        DWORD read = 0;
        DWORD chunk = remaining > 65536 ? 65536 : static_cast<DWORD>(remaining);
        BOOL ok = ReadFile(pipe, ptr, chunk, &read, nullptr);
        if (!ok || read == 0) {
            return false;
        }
        ptr += read;
        remaining -= read;
    }
    return true;
}

std::string PipeServer::serialize(const nlohmann::json& payload) const {
    return payload.dump();
}

}
