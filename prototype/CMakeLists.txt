#
#
#    SysmonForLinux
#
#    Copyright (c) Microsoft Corporation
#
#    All rights reserved.
#
#    MIT License
#
#    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
#    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
#    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
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
#    $ cmake ..                                                                 #
#    $ make                                                                     #
#                                                                               #
#################################################################################
# TIP:                                                                          #
# If this CMake file stops working, it could be because you're using a newer    #
# kernel source and the include files have moved. A simple way of finding the   #
# correct list of include directories is to modify the Makefiles in the kernel  #
# source in ${LINUX_SRC}/samples/bpf and ${LINUX_SRC}/tools/lib/bpf and add the #
# -v switch to the compiler. This will cause it to output all the switches it   #
# was called with, plus all the directories it will search for headers.         #
#################################################################################


cmake_minimum_required(VERSION 3.10)
cmake_policy(SET CMP0048 NEW)
# set the project name
project(Sysmon VERSION 0.1)

# pass the version number to code
configure_file(sysmon_config.h.in sysmon_config.h)

find_package(LibXml2 2.0.0 REQUIRED)

# build the loader and EBPF programs
add_subdirectory(ebpf_loader)

# make sysmon
add_executable(sysmon sysmon.c parsexml.c)
add_dependencies(sysmon ebpf_loader)
target_link_libraries(sysmon ebpf_loader "${LIBXML2_LIBRARIES}")
target_include_directories(sysmon PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           "/usr/include"
                           "${LIBXML2_INCLUDE_DIR}"
                           )


