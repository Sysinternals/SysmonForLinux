#
#
#    SysmonForLinux
#
#    Copyright (c) Microsoft Corporation
#
#    All rights reserved.
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#


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
#    $ cmake ..  <-DDEBUG_K=On> : to print out kernel debugging to trace_pipe   #
#    $ make                                                                     #
#                                                                               #
#################################################################################


cmake_minimum_required(VERSION 3.0)
cmake_policy(SET CMP0048 NEW)

# set the project name
project(EBPF_Loader VERSION 0.1)

include(ExternalProject)

#Set option for Debug Outputs for eBPF programs
option(DEBUG_K "Enter debug mode" Off)


#Fetch libbpf
ExternalProject_Add(libbpf
    GIT_REPOSITORY https://github.com/libbpf/libbpf.git
#    GIT_TAG master
    GIT_TAG v0.1.0
    PREFIX ./libbpf
    CONFIGURE_COMMAND ""
    BUILD_COMMAND cd ../libbpf/src && bash -c "CFLAGS=\"-g -O2 -Werror -Wall -fPIC\" make"
    INSTALL_COMMAND ""
    )

set(libbpf_SOURCE_DIR ${CMAKE_BINARY_DIR}/ebpf_loader/libbpf/src/libbpf)

# make ebpf_loader
add_library(ebpf_loader SHARED ebpf_telemetry_loader.c)
add_definitions("-fPIC")
add_dependencies(ebpf_loader libbpf)
target_link_libraries(ebpf_loader ${libbpf_SOURCE_DIR}/src/libbpf.a elf z)

if (STOPLOOP)
    message("setting STOPLOOP Count=${STOPLOOP}")
    target_compile_definitions( ebpf_loader PUBLIC STOPLOOP=${STOPLOOP})
endif()

target_include_directories(ebpf_loader PUBLIC
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
set(EBPF_PROGS
               ebpf_telemetry_kern_raw_tp_sub4096
               ebpf_telemetry_kern_raw_tp_noloops
               ebpf_telemetry_kern_raw_tp
               ebpf_telemetry_kern_tp
)



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
                   -I "${CMAKE_SOURCE_DIR}"
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
                       COMMAND "${CLANG}" -nostdinc -isystem `gcc -print-file-name=include` ${CLANG_INCLUDES} ${CLANG_DEFINES} -O2 ${CLANG_OPTIONS} -emit-llvm -c "${CMAKE_SOURCE_DIR}/ebpf_loader/ebpf_kern/${ebpfsrc}.c" -o -| "${LLC}" -march=bpf -filetype=obj -o "${ebpfsrc}.o"
                       COMMENT "Building EBPF object ${ebpfsrc}.o"
                       DEPENDS ebpf_kern/${ebpfsrc}.c
                       DEPENDS libbpf
                       DEPENDS ../sysmon_defs.h
                       DEPENDS ebpf_kern/ebpf_kern_helpers.c
                       DEPENDS ebpf_kern/ebpf_kern_common.h
                       DEPENDS ebpf_kern/ebpf_kern_tp.c
                       DEPENDS ebpf_kern/ebpf_kern_raw_tp.c
                       )
endfunction()

# loop for all ebpf programs
foreach(EBPF_PROG IN LISTS EBPF_PROGS)
    
    # add custom target to build all ebpf programs with 'all'
    add_custom_target(${EBPF_PROG} ALL
                      DEPENDS ${EBPF_PROG}.o
                      )

    # test to only build ebpf programs when they have changed
    if(${CMAKE_SOURCE_DIR}/ebpf_loader/ebpf_kern/${EBPF_PROG}.c IS_NEWER_THAN ${CMAKE_BINARY_DIR}/${EBPF_PROG}.o)
        build_ebpf(${EBPF_PROG})
    endif()

    # add ebpf programs to clean
    set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES ${EBPF_PROG}.o)
endforeach(EBPF_PROG)


