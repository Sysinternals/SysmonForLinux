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


#include "ebpf_kern_helpers.c"

// generic sys_enter argument struct for traditional tracepoints. Note that
// some or all of the 'a' array can't be derefenced depending on how many
// arguments a syscall expects; attempts to do so will cause the verifier
// to reject it.
struct tracepoint__syscalls__sys_enter {
    __uint64_t pad;
    __uint32_t __syscall_nr;
    __uint32_t pad2;
    __uint64_t a[6];
};

// all sys_exit arguments are the same for traditional tracepoints.
struct tracepoint__syscalls__sys_exit {
    __uint64_t pad;
    __uint32_t __syscall_nr;
    __uint32_t pad2;
     long ret;
};


// sys_enter for 0 arguments
SEC("tracepoint/syscalls/sys_enter0")
__attribute__((flatten))
int sys_enter0(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, syscall, pid_tid, cpu_id))
        return 0;

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_enter for 1 argument
SEC("tracepoint/syscalls/sys_enter1")
__attribute__((flatten))
int sys_enter1(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, syscall, pid_tid, cpu_id))
        return 0;

    event_args->a[0] = args->a[0];

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_enter for 2 arguments
SEC("tracepoint/syscalls/sys_enter2")
__attribute__((flatten))
int sys_enter2(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, syscall, pid_tid, cpu_id))
        return 0;

    event_args->a[0] = args->a[0];
    event_args->a[1] = args->a[1];

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_enter for 3 arguments
SEC("tracepoint/syscalls/sys_enter3")
__attribute__((flatten))
int sys_enter3(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, syscall, pid_tid, cpu_id))
        return 0;

    event_args->a[0] = args->a[0];
    event_args->a[1] = args->a[1];
    event_args->a[2] = args->a[2];

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_enter for 4 arguments
SEC("tracepoint/syscalls/sys_enter4")
__attribute__((flatten))
int sys_enter4(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, syscall, pid_tid, cpu_id))
        return 0;

    event_args->a[0] = args->a[0];
    event_args->a[1] = args->a[1];
    event_args->a[2] = args->a[2];
    event_args->a[3] = args->a[3];

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_enter for 5 arguments
SEC("tracepoint/syscalls/sys_enter5")
__attribute__((flatten))
int sys_enter5(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, syscall, pid_tid, cpu_id))
        return 0;

    event_args->a[0] = args->a[0];
    event_args->a[1] = args->a[1];
    event_args->a[2] = args->a[2];
    event_args->a[3] = args->a[3];
    event_args->a[4] = args->a[4];

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_enter for 6 arguments
SEC("tracepoint/syscalls/sys_enter6")
__attribute__((flatten))
int sys_enter6(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = args->__syscall_nr;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, syscall, pid_tid, cpu_id))
        return 0;

    event_args->a[0] = args->a[0];
    event_args->a[1] = args->a[1];
    event_args->a[2] = args->a[2];
    event_args->a[3] = args->a[3];
    event_args->a[4] = args->a[4];
    event_args->a[5] = args->a[5];

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

// sys_exit
SEC("tracepoint/syscalls/sys_exit")
__attribute__((flatten))
int sys_exit(struct tracepoint__syscalls__sys_exit *args)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint32_t cpu_id = bpf_get_smp_processor_id();
    event_s *event = NULL;
    args_s *event_args = NULL;
    uint32_t config_id = 0;
    config_s *config;
    uint32_t userland_pid = 0;
    void *task;
    void *p_task;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return 0;

    userland_pid = config->userland_pid;

    // don't report any syscalls for the userland PID
    if ((pid_tid >> 32) == userland_pid)
        return 0;

    // retrieve map storage for event args
    // this was created on the preceding sys_enter
    // if the pid_tid is in our map then we must have stored it
    event_args = bpf_map_lookup_elem(&args_hash, &pid_tid);
    if (!event_args)
        // otherwise bail
        return 0;

    // retrieve map storage for event
    event = bpf_map_lookup_elem(&event_storage_map, &cpu_id);
    if (!event)
        return 0;

    init_event(event, event_args, pid_tid >> 32);

    // set the return code
    event->return_code = args->ret;

    // get the task struct
    task = (void *)bpf_get_current_task();
    if (!task) {
        event->status |= STATUS_NOTASK;
    } else {
        p_task = (void *)deref_ptr(task, config->parent);
        set_event_exit_info(event, task, p_task, config);
        set_event_arg_info(event, task, p_task, config, cpu_id);
    }

    check_and_send_event((void *)args, event, config);

    // Cleanup
    bpf_map_delete_elem(&args_hash, &pid_tid);

    return 0;
}



