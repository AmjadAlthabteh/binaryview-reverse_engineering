cmake_minimum_required(VERSION 3.25)
project(BinView
    VERSION 1.0.0
    DESCRIPTION "PE File Analyzer & Import Reconstructor"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# vcpkg integration — set VCPKG_ROOT env var or pass -DCMAKE_TOOLCHAIN_FILE
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "vcpkg toolchain file")
endif()

find_package(capstone CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

# ── Main executable ──────────────────────────────────────────────────────────

add_executable(binview src/main.cpp)

target_include_directories(binview PRIVATE src)

target_link_libraries(binview PRIVATE
    capstone::capstone
    nlohmann_json::nlohmann_json
)

if(MSVC)
    target_compile_options(binview PRIVATE
        /W4
        /permissive-
        /Zc:__cplusplus
        /utf-8
        /std:c++latest
    )
    target_compile_definitions(binview PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        UNICODE
        _UNICODE
        _CRT_SECURE_NO_WARNINGS
    )
    # Enable ANSI output in CRT
    target_compile_definitions(binview PRIVATE _WIN32_WINNT=0x0A00)
endif()

# ── Tests ────────────────────────────────────────────────────────────────────

enable_testing()
add_subdirectory(tests)
