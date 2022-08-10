cmake_minimum_required(VERSION 3.11)

project(wasm-fuzz LANGUAGES C CXX)

find_package(PkgConfig REQUIRED)

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "No build type selected, default to Release")
    set(CMAKE_BUILD_TYPE "Release")
endif()

#set(CMAKE_CXX_FLAGS "-g -fsanitize=address -fno-omit-frame-pointer")
#set(CMAKE_C_FLAGS "-g -fsanitize=address -fno-omit-frame-pointer")
#SET (CMAKE_C_COMPILER clang)
#SET (CMAKE_CXX_COMPILER clang++)

if (CMAKE_BUILD_TYPE MATCHES "Release")
    set(CMAKE_CXX_FLAGS "-O3 -fsanitize=fuzzer,address -DV8_COMPRESS_POINTERS")
    set(CMAKE_C_FLAGS "-O3 -fsanitize=fuzzer,address -DV8_COMPRESS_POINTERS")
elseif (CMAKE_BUILD_TYPE MATCHES "ONLYDebug")
    set(CMAKE_CXX_FLAGS "-O0 -DDEBUG -g")
    set(CMAKE_C_FLAGS "-O0 -DDEBUG -g")
elseif (CMAKE_BUILD_TYPE MATCHES "DebugMEM")
    set(CMAKE_CXX_FLAGS "-O0 -DDEBUG -DDEBUG_MEM -g -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS "-O0 -DDEBUG -DDEBUG_MEM -g -fsanitize=address -fno-omit-frame-pointer")
elseif (CMAKE_BUILD_TYPE MATCHES "Debug")
    set(CMAKE_CXX_FLAGS "-O0 -DDEBUG -g -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS "-O0 -DDEBUG -g -fsanitize=address -fno-omit-frame-pointer")
endif()

add_subdirectory(WAGenMutate)

link_directories(wasmedge wasm3 wasmer wasmtime v8 JavaScriptCore)

pkg_check_modules(LB_LIBS REQUIRED)


add_executable(fuzzer_edge fuzzer_edge.cpp)

add_executable(fuzzer_wasm3 fuzzer_wasm3.cpp)

add_executable(fuzzer_wasmer fuzzer_wasmer.cpp)

add_executable(fuzzer_wasmtime fuzzer_wasmtime.cpp)

add_executable(fuzzer_v8 fuzzer_v8.cpp)

add_executable(fuzzer_jsc fuzzer_jsc.cpp)

set(WAGenMutate_PATH WAGenMutate/src)

include_directories(include ${WAGenMutate_PATH}/include wasmedge/include
                    ${WAGenMutate_PATH}/include/sections ${LB_LIBS_INCLUDE_DIRS}
                    wasm3 wasmer wasmtime v8 v8/include JavaScriptCore ./)

target_link_libraries(fuzzer_edge PUBLIC WAGenMutate wasmedge_c)
target_link_libraries(fuzzer_wasm3 PUBLIC WAGenMutate m3 uvwasi_a uv_a)
target_link_libraries(fuzzer_wasmer PUBLIC WAGenMutate wasmer)
target_link_libraries(fuzzer_wasmtime PUBLIC WAGenMutate wasmtime)
target_link_libraries(fuzzer_v8 PUBLIC WAGenMutate v8_monolith)
target_link_libraries(fuzzer_jsc PUBLIC WAGenMutate JavaScriptCore)

set_target_properties(fuzzer_edge PROPERTIES
        CXX_STANDARD 17
        C_STANDARD 99
        )
set_target_properties(fuzzer_wasm3 PROPERTIES
        CXX_STANDARD 17
        C_STANDARD 99
        )
