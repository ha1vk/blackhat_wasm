cmake_minimum_required(VERSION 3.11)

project(WAGenMutate CXX)

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
    set(CMAKE_CXX_FLAGS "-O3")
    set(CMAKE_C_FLAGS "-O3")
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

set(WAGenMutate_PATH src)


set(SOURCE  #src/main.cpp
            src/instructions.cpp
            src/random.cpp
            src/values.cpp
            src/leb128.cpp
            src/context.cpp
            src/config.cpp
            src/data_output_stream.cpp
            src/sections/section.cpp
            src/sections/code_section.cpp
            src/sections/custom_section.cpp
            src/sections/data_section.cpp
            src/sections/elem_section.cpp
            src/sections/export_section.cpp
            src/sections/function_section.cpp
            src/sections/global_section.cpp
            src/sections/import_section.cpp
            src/sections/memory_section.cpp
            src/sections/start_section.cpp
            src/sections/table_section.cpp
            src/sections/type_section.cpp
            src/wasm_structure.cpp
            src/global_classes_list.cpp
    )


add_executable(generator ${SOURCE} src/main.cpp)
add_executable(data2wasm ${SOURCE} src/data2wasm.cpp)

add_library(${PROJECT_NAME} ${SOURCE})
#${WAGenMutate_PATH}/include/sections

include_directories(${WAGenMutate_PATH}/include ${WAGenMutate_PATH}/include/sections
                    ${LB_LIBS_INCLUDE_DIRS})

target_link_options(${PROJECT_NAME} PRIVATE ${LB_LIBS_LDFLAGS})
target_link_libraries(${PROJECT_NAME} ${LB_LIBS_LIBRARIES})

set_target_properties(${PROJECT_NAME} PROPERTIES
        CXX_STANDARD 11
        C_STANDARD 99
        )
