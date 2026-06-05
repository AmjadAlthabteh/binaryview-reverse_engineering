find_package(Catch2 CONFIG REQUIRED)

add_executable(binview_tests
    test_main.cpp
    test_entropy.cpp
    test_pe_parser.cpp
)

target_include_directories(binview_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)

target_link_libraries(binview_tests PRIVATE
    Catch2::Catch2WithMain
    capstone::capstone
    nlohmann_json::nlohmann_json
)

if(MSVC)
    target_compile_options(binview_tests PRIVATE
        /W4
        /permissive-
        /Zc:__cplusplus
        /utf-8
        /std:c++latest
    )
    target_compile_definitions(binview_tests PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )
endif()

include(CTest)
include(Catch)
catch_discover_tests(binview_tests)
