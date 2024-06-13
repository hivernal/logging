cmake_minimum_required(VERSION 3.26)
project(audit CXX)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(BPF_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/audit")
set(BPFTOOL "${CMAKE_CURRENT_SOURCE_DIR}/bpftool/src/bpftool")
set(NAME audit)

set(SRC
  audit/main.cpp
  audit/database.cpp
  audit/bpf.cpp
  audit/audit_database.cpp
)
set(INCLUDE ${CMAKE_CURRENT_SOURCE_DIR})
set(mysql-concpp_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mysql")
set(LIB ssl mysql::concpp-jdbc bpf)
set(INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}")

add_custom_command(
  OUTPUT skel
  COMMAND clang "${BPF_SOURCE_DIR}/${NAME}.bpf.c" -c -g -O2 -target bpf
          -D__TARGET_ARCH_x86 -o "${NAME}.bpf.o"
  COMMAND "${BPFTOOL}" gen skeleton "${NAME}.bpf.o" >
          "${BPF_SOURCE_DIR}/${NAME}.skel.h"
)

find_package(mysql-concpp REQUIRED)
add_executable(audit ${SRC} skel)
target_include_directories(audit SYSTEM PRIVATE ${INCLUDE})
target_link_libraries(audit PRIVATE ${LIB})
target_compile_options(audit
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
