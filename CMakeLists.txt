# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.14)

project(sha2_toolkit
        VERSION 1.0.0
        DESCRIPTION "Dependency-free SHA-2 cryptographic toolkit (SHA-224/256, HMAC, HKDF, PBKDF2, HOTP/TOTP)"
        LANGUAGES CXX)

# ---- Options -----------------------------------------------------------------
option(SHA2_BUILD_TESTS    "Build the test suite"        ON)
option(SHA2_BUILD_TOOLS    "Build the sha2 CLI"          ON)
option(SHA2_BUILD_BENCH    "Build the benchmark"         ON)
option(SHA2_BUILD_FUZZERS  "Build libFuzzer targets (Clang only)" OFF)
option(SHA2_ENABLE_ASAN    "Build with AddressSanitizer + UBSan"  OFF)

# ---- Header-only library -----------------------------------------------------
add_library(sha2 INTERFACE)
add_library(sha2::sha2 ALIAS sha2)
target_include_directories(sha2 INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(sha2 INTERFACE cxx_std_17)

# ---- Shared compile flags ----------------------------------------------------
add_library(sha2_flags INTERFACE)
if(MSVC)
    target_compile_options(sha2_flags INTERFACE /W4 /permissive-)
else()
    target_compile_options(sha2_flags INTERFACE -Wall -Wextra -Wpedantic)
endif()

if(SHA2_ENABLE_ASAN AND NOT MSVC)
    target_compile_options(sha2_flags INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(sha2_flags INTERFACE -fsanitize=address,undefined)
endif()

# ---- CLI ---------------------------------------------------------------------
if(SHA2_BUILD_TOOLS)
    add_executable(sha2_cli tools/sha2.cpp)
    set_target_properties(sha2_cli PROPERTIES OUTPUT_NAME sha2)
    target_link_libraries(sha2_cli PRIVATE sha2 sha2_flags)
endif()

# ---- Benchmark ---------------------------------------------------------------
if(SHA2_BUILD_BENCH)
    add_executable(sha2_bench bench/bench.cpp)
    target_link_libraries(sha2_bench PRIVATE sha2 sha2_flags)
    target_compile_options(sha2_bench PRIVATE $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O3>)
endif()

# ---- Tests -------------------------------------------------------------------
if(SHA2_BUILD_TESTS)
    enable_testing()
    set(SHA2_TESTS
        test_sha256
        test_hmac
        test_hkdf
        test_pbkdf2
        test_otp
        test_kat_corpus)
    foreach(t ${SHA2_TESTS})
        add_executable(${t} tests/${t}.cpp)
        target_include_directories(${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        target_link_libraries(${t} PRIVATE sha2 sha2_flags)
        add_test(NAME ${t} COMMAND ${t})
    endforeach()
endif()

# ---- Fuzzers (Clang only) ----------------------------------------------------
if(SHA2_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "SHA2_BUILD_FUZZERS requires Clang (libFuzzer).")
    endif()
    foreach(f fuzz_sha256 fuzz_hmac)
        add_executable(${f} fuzz/${f}.cpp)
        target_link_libraries(${f} PRIVATE sha2)
        target_compile_options(${f} PRIVATE -g -O1 -fsanitize=fuzzer,address,undefined)
        target_link_options(${f} PRIVATE -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()

# ---- Install -----------------------------------------------------------------
include(GNUInstallDirs)
install(DIRECTORY include/sha2 DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(SHA2_BUILD_TOOLS)
    install(TARGETS sha2_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
