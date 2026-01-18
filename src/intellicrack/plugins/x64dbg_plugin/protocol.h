#pragma once

#include <cstdint>

namespace intellicrack {

constexpr const wchar_t* kPipeName = L"\\\\.\\pipe\\intellicrack_x64dbg";
constexpr std::uint32_t kMaxMessageSize = 8 * 1024 * 1024;

}
