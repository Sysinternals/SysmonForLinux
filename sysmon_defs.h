/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

//====================================================================
//
// sysmon_defs.h
//
// Defines and types needed by Sysmon for Linux.
//
//====================================================================

#ifndef SYSMON_DEFS_H
#define SYSMON_DEFS_H

#include <linux/limits.h>
#include "linuxTypes.h"
#include "sysmonmsgop.h"
#include "ioctlcmd.h"

#define SYSMON_UMASK            077

#define SYSMON_INSTALL_DIR      "/opt/sysmon"
#define SYSMON_EULA_FILE        SYSMON_INSTALL_DIR "/eula_accepted"
#define EVENTID_FILE            SYSMON_INSTALL_DIR "/eventId"
#define SYSMON_CONFIG_FILE      SYSMON_INSTALL_DIR "/config.xml"
#define SYSMON_RULES_FILE       SYSMON_INSTALL_DIR "/rules.bin"
#define SYSMON_ARGC_FILE        SYSMON_INSTALL_DIR "/argc"
#define SYSMON_ARGV_FILE        SYSMON_INSTALL_DIR "/argv"
#define SYSMON_FIELDSIZES_FILE  SYSMON_INSTALL_DIR "/fieldSizes"

#define SYSMON_EBPF_DIR         "sysinternalsEBPF"
#define PROC_EXE_PATH           "/proc/self/exe"
#define PROC_STAT_PATH          "/proc/self/stat"
#define PROC_EXE_PATH_FMT       "/proc/%d/exe"
#define SYSMON_BINARY           "sysmon"
#define EBPFLIB                 "libsysinternalsEBPF.so"
#define MEM_DUMP_OBJ            "sysinternalsEBPFmemDump.o"
#define RAW_SOCK_OBJ            "sysinternalsEBPFrawSock.o"
#define KERN_4_15_OBJ           "sysmonEBPFkern4.15.o"
#define KERN_4_16_OBJ           "sysmonEBPFkern4.16.o"
#define KERN_4_17_5_1_OBJ       "sysmonEBPFkern4.17-5.1.o"
#define KERN_5_2_OBJ            "sysmonEBPFkern5.2.o"
#define KERN_5_3_5_5_OBJ        "sysmonEBPFkern5.3-5.5.o"
#define KERN_5_6__OBJ           "sysmonEBPFkern5.6-.o"
#define SYSMONLOGVIEW_BINARY    "sysmonLogView"
#define SYSTEMD_DIR             "/etc/systemd/system"
#define SYSTEMD_SERVICE         "sysmon.service"
#define SYSTEMD_RELOAD_CMD      "systemctl daemon-reload"
#define SYSTEMD_START_CMD       "systemctl start"
#define SYSTEMD_STOP_CMD        "systemctl stop"
#define SYSTEMD_ENABLE_CMD      "systemctl enable"
#define SYSTEMD_DISABLE_CMD     "systemctl disable"
#define INITD_DIR               "/etc/init.d"
#define INITD_SERVICE           "sysmon"
#define INITD_DIR_FMT           "/etc/rc%d.d"
#define INITD_START_ID          "S99"
#define INITD_KILL_ID           "K99"

#define UDP_REPORT_INTERVAL     (30L * 60 * 1000 * 1000 * 10) // 30 minutes in 100ns intervals
#define UDP_HASH_SIZE           (128 * 1024)
#define UDP_HASH_RPP            0.1 // rapid purge proportion - volume of observations to remove
#define UDP_PIDFD_HASH          0
#define UDP_ADDRS_HASH          1

#define PACKET_SIZE             128
#define PACKET_MASK             (PACKET_SIZE - 1)

#define PROTO_IPV4              0x0800
#define PROTO_IPV6              0x86DD
#define PROTO_UDP               0x11

// return values
#define READ_OKAY               0
#define UPDATE_OKAY             0

typedef struct {
    bool                        IPv4;
    BYTE                        srcAddr[16];
    unsigned short              srcPort;
    BYTE                        dstAddr[16];
    unsigned short              dstPort;
} packetAddrs;

#endif
