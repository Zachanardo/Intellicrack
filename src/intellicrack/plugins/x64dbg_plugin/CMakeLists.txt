cmake_minimum_required(VERSION 3.20)
project(intellicrack_x64dbg_plugin LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(X64DBG_SDK_PATH "" CACHE PATH "Path to x64dbg SDK")
if(NOT X64DBG_SDK_PATH)
    if(DEFINED ENV{X64DBG_SDK_PATH})
        set(X64DBG_SDK_PATH $ENV{X64DBG_SDK_PATH})
    endif()
endif()

find_path(
    X64DBG_INCLUDE_DIR
    plugin.h
    PATHS
        "${X64DBG_SDK_PATH}"
        "${X64DBG_SDK_PATH}/include"
        "${X64DBG_SDK_PATH}/sdk"
        "${X64DBG_SDK_PATH}/x64dbg/sdk"
)

if(NOT X64DBG_INCLUDE_DIR)
    message(FATAL_ERROR "x64dbg SDK not found. Set X64DBG_SDK_PATH.")
endif()

add_library(intellicrack_x64dbg SHARED
    intellicrack_x64dbg.cpp
    pipe_server.cpp
    command_handler.cpp
    event_handler.cpp
)

target_include_directories(intellicrack_x64dbg PRIVATE
    ${X64DBG_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(intellicrack_x64dbg PRIVATE UNICODE _UNICODE)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(intellicrack_x64dbg PROPERTIES SUFFIX ".dp64")
else()
    set_target_properties(intellicrack_x64dbg PROPERTIES SUFFIX ".dp32")
endif()

find_library(
    X64DBG_LIB
    x64dbg
    PATHS
        "${X64DBG_SDK_PATH}/lib"
        "${X64DBG_SDK_PATH}/lib64"
)

if(X64DBG_LIB)
    target_link_libraries(intellicrack_x64dbg PRIVATE ${X64DBG_LIB})
endif()

target_link_libraries(intellicrack_x64dbg PRIVATE Rpcrt4)
