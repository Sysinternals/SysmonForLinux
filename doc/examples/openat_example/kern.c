/*
    eBPF openat example

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
#include "event_defs.h"

#define BPF_F_INDEX_MASK		0xffffffffULL
#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK

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

// SYSCALL_PT_REGS defines
#define SYSCALL_PT_REGS_PARM1(x) ((x)->rdi)
#define SYSCALL_PT_REGS_PARM2(x) ((x)->rsi)
#define SYSCALL_PT_REGS_PARM3(x) ((x)->rdx)
#define SYSCALL_PT_REGS_PARM4(x) ((x)->r10)
#define SYSCALL_PT_REGS_PARM5(x) ((x)->r8)
#define SYSCALL_PT_REGS_PARM6(x) ((x)->r9)
#define SYSCALL_PT_REGS_RC(x)    ((x)->rax)

#define MAX_CPU 512

// Create a map for the perf ring buffer
struct bpf_map_def SEC("maps") event_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(uint32_t),
	.max_entries = MAX_CPU, // 512 CPUs - this needs to accommodate most systems so make this big
                        // Also, as this map is quite small (8 bytes per entry), we could potentially
                        // make this even bigger and it woulnd't cost much
};

// Create a map to store arguments between enter and exit
struct bpf_map_def SEC("maps") event_args_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(event_args_s),
    .max_entries = 16384,
};

// create a map to hold the event as we build it - too big for stack
// one entry per cpu
struct bpf_map_def SEC("maps") event_storage_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(event_s),
    .max_entries = MAX_CPU,
};

// structs for tracepoint arguments
struct tracepoint__syscalls__sys_enter_openat {
    uint64_t pad;
    uint32_t syscall_nr;
    uint32_t pad2;
    int64_t dfd;
    const char *filename;
    uint64_t flags;
    uint64_t mode;
};

struct tracepoint__syscalls__sys_exit_openat {
    uint64_t pad;
    uint32_t syscall_nr;
    uint32_t pad2;
    int64_t ret;
};

struct tracepoint__raw_syscalls__sys_enter {
    uint64_t pad;
    uint64_t id;
    uint64_t args[6];
};

struct tracepoint__raw_syscalls__sys_exit {
    uint64_t pad;
    uint64_t id;
    int64_t ret;
};

struct bpf_our_raw_tracepoint_args {
    __u64 args[0];
};



SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct tracepoint__syscalls__sys_enter_openat *ctx)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    event_args_s event_args;

    // zero the memory
    memset(&event_args, 0, sizeof(event_args));
    event_args.syscall = __NR_openat;

    event_args.args[0] = (uint64_t)ctx->dfd;
    event_args.args[1] = (uint64_t)ctx->filename;
    event_args.args[2] = (uint64_t)ctx->flags;
    event_args.args[3] = (uint64_t)ctx->mode;

    bpf_map_update_elem(&event_args_map, &pid_tgid, &event_args, BPF_ANY);

    return 0;
}

__attribute__((always_inline))
static inline void openat_exit(void *ctx, int64_t ret)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t map_id = bpf_get_smp_processor_id();
    event_s *event = NULL;
    event_args_s *event_args = NULL;
    int size = 0;
    void *exe = NULL;

    // retrieve arguments
    event_args = bpf_map_lookup_elem(&event_args_map, &pid_tgid);
    if (event_args == NULL)
        return;

    // bail if not openat
    if (event_args->syscall != __NR_openat)
        return;

    // bail if openat was unsuccessful
    if (ret < 0) {
        bpf_map_delete_elem(&event_args_map, &pid_tgid);
        return;
    }

    // get memory for event
    event = bpf_map_lookup_elem(&event_storage_map, &map_id);
    if (event == NULL) {
        bpf_map_delete_elem(&event_args_map, &pid_tgid);
        return;
    }

    event->pid = pid_tgid >> 32;
    event->flags = event_args->args[2];
    event->mode = event_args->args[3];

    size = bpf_probe_read_str(event->filename, sizeof(event->filename), (void *)(event_args->args[1]));

    if (size > 0) {
        bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, event, size + (3 * sizeof(uint64_t)));
    }

    bpf_map_delete_elem(&event_args_map, &pid_tgid);
}

SEC("tracepoint/syscalls/sys_exit_openat")
__attribute__((flatten))
int tracepoint__syscalls__sys_exit_openat(struct tracepoint__syscalls__sys_exit_openat *ctx)
{
    openat_exit(ctx, ctx->ret);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct tracepoint__raw_syscalls__sys_enter *ctx)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    event_args_s event_args;
    uint32_t syscall = ctx->id;

    // bail if this isn't an openat
    if (syscall != __NR_openat)
        return 0;

    // zero the memory
    memset(&event_args, 0, sizeof(event_args));
    event_args.syscall = syscall;

    event_args.args[0] = ctx->args[0];
    event_args.args[1] = ctx->args[1];
    event_args.args[2] = ctx->args[2];
    event_args.args[3] = ctx->args[3];

    bpf_map_update_elem(&event_args_map, &pid_tgid, &event_args, BPF_ANY);

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
__attribute__((flatten))
int tracepoint__raw_syscalls__sys_exit(struct tracepoint__raw_syscalls__sys_exit *ctx)
{
    openat_exit(ctx, ctx->ret);
    return 0;
}

SEC("raw_tracepoint/raw_syscalls/sys_enter")
int raw_tracepoint__raw_syscalls__sys_enter(struct bpf_our_raw_tracepoint_args *ctx)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    event_args_s event_args;
    uint32_t syscall = ctx->args[1];

    // bail if this isn't an openat
    if (syscall != __NR_openat)
        return 0;

    // zero the memory
    memset(&event_args, 0, sizeof(event_args));
    event_args.syscall = syscall;

    const struct pt_regs *regs = (const struct pt_regs *)ctx->args[0];

    bpf_probe_read(&event_args.args[0], sizeof(event_args.args[0]), &SYSCALL_PT_REGS_PARM1(regs));
    bpf_probe_read(&event_args.args[1], sizeof(event_args.args[1]), &SYSCALL_PT_REGS_PARM2(regs));
    bpf_probe_read(&event_args.args[2], sizeof(event_args.args[2]), &SYSCALL_PT_REGS_PARM3(regs));
    bpf_probe_read(&event_args.args[3], sizeof(event_args.args[3]), &SYSCALL_PT_REGS_PARM4(regs));

    bpf_map_update_elem(&event_args_map, &pid_tgid, &event_args, BPF_ANY);

    return 0;
}

SEC("raw_tracepoint/raw_syscalls/sys_exit")
__attribute__((flatten))
int raw_tracepoint__raw_syscalls__sys_exit(struct bpf_our_raw_tracepoint_args *ctx)
{
    int64_t ret = 0;

    const struct pt_regs *regs = (const struct pt_regs *)ctx->args[0];

    bpf_probe_read(&ret, sizeof(ret), &SYSCALL_PT_REGS_RC(regs));

    openat_exit(ctx, ret);
    return 0;
}

char _license[] SEC("license") = "GPL";
