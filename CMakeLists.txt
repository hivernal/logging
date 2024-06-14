cmake_minimum_required(VERSION 3.26)
project(logging CXX)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(BPF_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/logging")
set(BPFTOOL_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src")
set(BPFTOOL "${BPFTOOL_SOURCE_DIR}/bpftool")
set(NAME logging)

set(SRC
  logging/main.cpp
  logging/database.cpp
  logging/bpf.cpp
  logging/audit_database.cpp
)

set(INCLUDE ${CMAKE_CURRENT_SOURCE_DIR})
set(LIB pqxx bpf)
set(LIBPQXX_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libpqxx)
set(LIBPQXX_INCLUDE ${LIBPQXX_DIR}/include)
set(INCLUDE ${CMAKE_CURRENT_SOURCE_DIR} ${LIBPQXX_INCLUDE})

add_custom_target(bpftool
  ALL COMMAND make -C "${BPFTOOL_SOURCE_DIR}"
)

add_custom_command(
  OUTPUT skel
  COMMAND clang "${BPF_SOURCE_DIR}/${NAME}.bpf.c" -c -g -O2 -target bpf
          -D__TARGET_ARCH_x86 -o "${NAME}.bpf.o"
  COMMAND "${BPFTOOL}" gen skeleton "${NAME}.bpf.o" >
          "${BPF_SOURCE_DIR}/${NAME}.skel.h"
)

add_subdirectory(${LIBPQXX_DIR})
add_executable(logging ${SRC} skel)
target_include_directories(logging SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(logging PRIVATE ${LIB})
target_compile_options(logging
  PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -Weffc++
    -Wconversion
    -Wsign-conversion
    -Wnon-virtual-dtor
    -Wold-style-cast
    -Wsign-promo
    -Wduplicated-branches
    -Wduplicated-cond
    -Wzero-as-null-pointer-constant
    -Wlogical-op
)
