cmake_minimum_required(VERSION 3.21)
project(windows_lsa_example)

set(CMAKE_CXX_STANDARD 14)

include(FetchContent)
include(thirdparty.cmake)

set(windows_lsa_example_LIBRARY_NAME ${CMAKE_PROJECT_NAME})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/dll.def.in ${CMAKE_CURRENT_BINARY_DIR}/dll.def @ONLY)

add_library(windows_lsa_example SHARED
        ${CMAKE_CURRENT_BINARY_DIR}/dll.def
        src/lsa_ap_main.h
        src/dll_main.cc
        src/sp_lsa_main.cc
        src/lsa_ap_main.cc
        src/lsa_functions.h
        src/lsa_functions.cc
        )
target_link_libraries(
        windows_lsa_example
        PRIVATE
        plog
)
target_compile_definitions(
        windows_lsa_example
        PRIVATE
        UNICODE _UNICODE
)
