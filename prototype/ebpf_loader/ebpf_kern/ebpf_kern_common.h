/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/


#ifndef KERN_COMMON_H
#define KERN_COMMON_H

#include <stdint.h>
#include <linux/version.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/fcntl.h>
#include <sys/socket.h>
#include <linux/string.h>
#include <asm/unistd_64.h>
#include <asm/ptrace.h>
#include "../../sysmon_defs.h"

// debug tracing can be found using:
// #cat /sys/kernel/debug/tracing/trace_pipe

#ifdef DEBUG_K
#define BPF_PRINTK( format, ... ) \
    char fmt[] = format; \
    bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__ ); 
#else
#define BPF_PRINTK ((void)0);
#endif

// missing stddef.h defines
#define NULL ((void *)0)
typedef int bool;
#define true 1
#define false 0

// x64 syscall macros
#define SYSCALL_PT_REGS_PARM1(x) ((x)->rdi)
#define SYSCALL_PT_REGS_PARM2(x) ((x)->rsi)
#define SYSCALL_PT_REGS_PARM3(x) ((x)->rdx)
#define SYSCALL_PT_REGS_PARM4(x) ((x)->r10)
#define SYSCALL_PT_REGS_PARM5(x) ((x)->r8)
#define SYSCALL_PT_REGS_PARM6(x) ((x)->r9)
#define SYSCALL_PT_REGS_RC(x)    ((x)->rax)

// bpf_raw_tracepoint_args definition from /usr/src/linux/include/uapi/linux/bpf.h
struct bpf_our_raw_tracepoint_args {
        __u64 args[0];
};


#define MAX_PROC 512
#define ARGS_HASH_SIZE 10240
#define SYSCONF_MAP_SIZE 10240

#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU 0xffffffffULL
#endif

// creat a map to transport events to userland via perf ring buffer
struct bpf_map_def SEC("maps") event_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, //BPF_MAP_TYPE_HASH doesnt stack....
	.key_size = sizeof(int),
	.value_size = sizeof(uint32_t),
	.max_entries = MAX_PROC, // MAX_PROC CPUs - this needs to accommodate most systems as this is CO:RE-alike
                        // Also, as this map is quite small (8 bytes per entry), we could potentially
                        // make this event bigger and it woulnd't cost much
};

// create a map to hold the event as we build it - too big for stack
// one entry per cpu
struct bpf_map_def SEC("maps") event_storage_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(event_s),
    .max_entries = MAX_PROC,
};

// create a map to hold the args as we build it - too big for stack
// one entry per cpu
struct bpf_map_def SEC("maps") args_storage_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(args_s),
    .max_entries = MAX_PROC,
};

// create a map to hold a temporary filepath as we build it - too big for stack
// one entry per cpu
struct bpf_map_def SEC("maps") temppath_array = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = PATH_MAX * 2,
    .max_entries = MAX_PROC,
};

// create a hash to hold event arguments between sys_enter and sys_exit
// shared by all cpus because sys_enter and sys_exit could be on different cpus
struct bpf_map_def SEC("maps") args_hash = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(args_s),
    .max_entries = ARGS_HASH_SIZE,
};

// create a map to hold the configuration
// only one entry, which is the config struct
struct bpf_map_def SEC("maps") config_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(config_s),
    .max_entries = 1,
};

// create a map to hold the syscall configuration
// key is (syscall << 16 | index)
// syscall indicies are per syscall, and each increments from 0
struct bpf_map_def SEC("maps") sysconf_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(sysconf_s),
    .max_entries = SYSCONF_MAP_SIZE,
};

#endif
