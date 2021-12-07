#    eBPF execve example
#
#    Copyright (c) Microsoft Corporation
#
#    All rights reserved.
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


#################################################################################
# NOTE:                                                                         #
# Due to the clever way that the EBPF programs are built, any modifications to  #
# this file can upset the CMake cache and cause upredictable building errors.   #
# To avoid this, firstly always build in a build directory, e.g.:               #
#                                                                               #
#    $ mkdir build; cd build                                                    #
#    $ cmake ..                                                                 #
#    $ make                                                                     #
#                                                                               #
# and subsequently, if the CMake cache does get upset, simply remove the build  #
# directory and start again with a fresh build directory, e.g.:                 #
#                                                                               #
#    $ cd ..                                                                    #
#    $ rm -rf build                                                             #
#    $ mkdir build; cd build                                                    #
#    $ cmake ..                                                                 #
#    $ make                                                                     #
#                                                                               #
#################################################################################


cmake_minimum_required(VERSION 3.10)

# set the project name
project(Sched_exec VERSION 1.0)

#
# enable Debug while pre-release; re-enable it post-release to add symbols to binary
#
set(CMAKE_BUILD_TYPE Debug)
option(DEBUG_K "Enter debug mode" On)

include(ExternalProject)

#Fetch libbpf
ExternalProject_Add(libbpf
    GIT_REPOSITORY https://github.com/libbpf/libbpf.git
    GIT_TAG v0.1.0
    PREFIX ./libbpf
    CONFIGURE_COMMAND ""
    BUILD_COMMAND cd ../libbpf/src && make
    INSTALL_COMMAND ""
    )

set(libbpf_SOURCE_DIR ${CMAKE_BINARY_DIR}/libbpf/src/libbpf)

# make ebpf_telemetry
add_executable(user user.c)
add_dependencies(user libbpf)
target_link_libraries(user ${libbpf_SOURCE_DIR}/src/libbpf.a elf z)
target_include_directories(user PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           "${libbpf_SOURCE_DIR}/src"
                           "${libbpf_SOURCE_DIR}/include"
                           "${libbpf_SOURCE_DIR}/include/asm"
                           "${libbpf_SOURCE_DIR}/include/linux"
                           "${libbpf_SOURCE_DIR}/include/tools"
                           "${libbpf_SOURCE_DIR}/include/uapi"
                           "${libbpf_SOURCE_DIR}/include/uapi/linux"
                           "/usr/include"
                           )

# list of ebpf programs to make
set(EBPF_PROGS kern)

########################################################
# Everything below this point should be fairly static. #
########################################################


#
# EBPF COMPILE OPTIONS
#
# This section specifies the options for building ebpf programs
#

# set binaries and options for clang and llc
set(CLANG "clang")
set(LLC "llc")
set(CLANG_OPTIONS -Wno-unused-value
                  -Wno-pointer-sign
                  -Wno-compare-distinct-pointer-types
                  -Wno-gnu-variable-sized-type-not-at-end
                  -Wno-address-of-packed-member
                  -Wno-tautological-compare
                  -Wno-unknown-warning-option
                  )
set(CLANG_DEFINES -D __KERNEL__
                  -D __BPF_TRACING__
                  -D __TARGET_ARCH_x86
                  )

if (DEBUG_K)
    message("Using DEBUG_K Option...")
    list(APPEND CLANG_DEFINES -DDEBUG_K)
endif()

set(CLANG_INCLUDES
                   -I "/usr/include"
                   -I "/usr/include/x86_64-linux-gnu"
                   -I "${libbpf_SOURCE_DIR}/src"
                   )

#
# EBPF
#
# This section makes the EBPF programs
#

# function to make ebpf programs
function(build_ebpf ebpfsrc)
    add_custom_command(OUTPUT ${ebpfsrc}.o
                       COMMAND "${CLANG}" -nostdinc -isystem `gcc -print-file-name=include` ${CLANG_INCLUDES} ${CLANG_DEFINES} -O2 ${CLANG_OPTIONS} -emit-llvm -c "${CMAKE_SOURCE_DIR}/${ebpfsrc}.c" -o -| "${LLC}" -march=bpf -filetype=obj -o "${ebpfsrc}.o"
                       COMMENT "Building EBPF object ${ebpfsrc}.o"
                       DEPENDS ${ebpfsrc}.c
                       DEPENDS libbpf
                       DEPENDS event_defs.h
                       )
endfunction()

# loop for all ebpf programs
foreach(EBPF_PROG IN LISTS EBPF_PROGS)
    
    # add custom target to build all ebpf programs with 'all'
    add_custom_target(${EBPF_PROG} ALL
                      DEPENDS ${EBPF_PROG}.o
                      )

    # test to only build ebpf programs when they have changed
    if(${CMAKE_SOURCE_DIR}/${EBPF_PROG}.c IS_NEWER_THAN ${CMAKE_BINARY_DIR}/${EBPF_PROG}.o)
        build_ebpf(${EBPF_PROG})
    endif()

    # add ebpf programs to clean
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${EBPF_PROG}.o)
endforeach(EBPF_PROG)


