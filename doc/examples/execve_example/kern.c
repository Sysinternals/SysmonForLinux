/*
    eBPF execve example

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

// missing PT_REGS defines
#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_PARM4(x) ((x)->rcx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_PARM6(x) ((x)->r9)
#define PT_REGS_RC(x)    ((x)->rax)

#define MAX_CPU 512

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
    .value_size = sizeof(event_s),
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

struct tracepoint__syscalls__sys_enter_execve {
    uint64_t pad;
    uint32_t syscall_nr;
    uint32_t pad2;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

struct tracepoint__syscalls__sys_exit_execve {
    uint64_t pad;
    uint32_t syscall_nr;
    uint32_t pad2;
    int64_t ret;
};

struct tracepoint__sched__sched_process_exec {
    uint64_t pad;
    uint32_t filename;
    uint32_t pid;
    uint32_t old_pid;
    char     data[65536];
};

struct tracepoint__sched__sched_process_fork {
    uint64_t pad;
    char     pcomm[16];
    uint32_t ppid;
    char     comm[16];
    uint32_t pid;
};

struct tracepoint__task__task_newtask {
    uint64_t pad;
    uint32_t pid;
    char     comm[16];
    uint64_t clone_flags;
    uint16_t oom_score_adj;
};


SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct tracepoint__syscalls__sys_enter_execve *ctx)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t map_id = bpf_get_smp_processor_id();
    event_s *event;
    int size = 0;

    // get memory for event
    event = bpf_map_lookup_elem(&event_storage_map, &map_id);
    if (event == NULL) {
        return 0;
    }

    event->pid = 0;
    event->ppid = 0;
    event->size = 0;
    event->type = 1;

    size = bpf_probe_read_str(event->exe, sizeof(event->exe), ctx->filename);
    if (size > 0) {
        event->size = size;
    }
    bpf_map_update_elem(&event_args_map, &pid_tgid, event, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct tracepoint__syscalls__sys_exit_execve *ctx)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t map_id = bpf_get_smp_processor_id();
    event_s *event = NULL;
    int size = 0;
    void *exe = NULL;

    // retrieve arguments
    event = bpf_map_lookup_elem(&event_args_map, &pid_tgid);
    if (event == NULL)
        return 0;

    // bail if exec was unsuccessful
    if (ctx->ret < 0) {
        bpf_map_delete_elem(&event_args_map, &pid_tgid);
        return 0;
    }

    event->pid = pid_tgid >> 32;

    size = event->size & 4095;
    bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, event, sizeof(*event) - sizeof(event->exe) + size);

    bpf_map_delete_elem(&event_args_map, &pid_tgid);

    return 0;
}

__attribute__((always_inline))
static inline void write_event(void *ctx, pid_t pid, pid_t ppid, int type, char *exe)
{
    uint32_t map_id = bpf_get_smp_processor_id();
    event_s *event;
    int size = 0;

    // get memory for event
    event = bpf_map_lookup_elem(&event_storage_map, &map_id);
    if (event == NULL) {
        return;
    }

    event->pid = pid;
    event->ppid = ppid;
    event->size = 0;
    event->type = type;

    size = bpf_probe_read_str(event->exe, sizeof(event->exe), exe);
    if (size > 0) {
        event->size = size;
    }

    size = event->size & 4095;
    bpf_perf_event_output(ctx, &event_map, BPF_F_CURRENT_CPU, event, sizeof(*event) - sizeof(event->exe) + size);
}

__attribute__((flatten))
SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct tracepoint__sched__sched_process_exec *ctx)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t offset = 0;

    offset = ctx->filename & 0xFFFF;
    write_event(ctx, pid_tgid >> 32, 0, 2, ((char *)ctx) + offset);

    return 0;
}

__attribute__((flatten))
SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct tracepoint__sched__sched_process_fork *ctx)
{
    write_event(ctx, ctx->pid, ctx->ppid, 3, ctx->comm);

    return 0;
}

__attribute__((flatten))
SEC("tracepoint/task/new_task")
int tracepoint__task__new_task(struct tracepoint__task__task_newtask *ctx)
{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();

    write_event(ctx, ctx->pid, pid_tgid >> 32, 4, ctx->comm);

    return 0;
}


char _license[] SEC("license") = "GPL";
