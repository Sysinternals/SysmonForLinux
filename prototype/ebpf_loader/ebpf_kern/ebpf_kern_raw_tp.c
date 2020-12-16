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


// store the syscall arguments from the registers in the event
__attribute__((always_inline))
static inline bool set_event_args(unsigned long *a, struct pt_regs *regs)
{
    int ret = 0;
    ret |= bpf_probe_read(&a[0], sizeof(a[0]), &SYSCALL_PT_REGS_PARM1(regs));
    ret |= bpf_probe_read(&a[1], sizeof(a[1]), &SYSCALL_PT_REGS_PARM2(regs));
    ret |= bpf_probe_read(&a[2], sizeof(a[2]), &SYSCALL_PT_REGS_PARM3(regs));
    ret |= bpf_probe_read(&a[3], sizeof(a[3]), &SYSCALL_PT_REGS_PARM4(regs));
    ret |= bpf_probe_read(&a[4], sizeof(a[4]), &SYSCALL_PT_REGS_PARM5(regs));
    ret |= bpf_probe_read(&a[5], sizeof(a[5]), &SYSCALL_PT_REGS_PARM6(regs));
    if (!ret)
        return true;
    else
        return false;
}

 
SEC("raw_tracepoint/sys_enter")
__attribute__((flatten))
int sys_enter(struct bpf_our_raw_tracepoint_args *ctx)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint32_t cpu_id = bpf_get_smp_processor_id();
    args_s *event_args;
    uint32_t syscall = ctx->args[1];
    uint32_t config_id = 0;
    config_s *config;
    char syscall_flags = 0;
    void *task;

    // retrieve config
    config = bpf_map_lookup_elem(&config_map, &config_id);
    if (!config)
        return 0;

    // bail early for syscalls we aren't interested in
    syscall_flags = config->active[syscall & (SYSCALL_ARRAY_SIZE - 1)];
    if (!(syscall_flags & ACTIVE_SYSCALL))
        return 0;

    // retrieve map storage for event
    event_args = bpf_map_lookup_elem(&args_storage_map, &cpu_id);
    if (!event_args)
        return 0;

    if (!sys_enter_check_and_init(event_args, syscall, pid_tid, cpu_id))
        return 0;

    // retrieve the register state
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    if (!set_event_args(event_args->a, regs)) {
        BPF_PRINTK("set_event_args failed\n");
    }

    sys_enter_complete_and_store(event_args, syscall, pid_tid);
    return 0;
}

SEC("raw_tracepoint/sys_exit")
__attribute__((flatten))
int sys_exit(struct bpf_our_raw_tracepoint_args *ctx)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint32_t cpu_id = bpf_get_smp_processor_id();
    event_s *event = NULL;
    args_s *event_args = NULL;
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
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
    if (bpf_probe_read(&event->return_code, sizeof(int64_t), (void *)&SYSCALL_PT_REGS_RC(regs)) != 0){
        BPF_PRINTK("ERROR, failed to get return code, exiting syscall %lu\n", event->syscall_id);
        event->status |= STATUS_RC;
    }

    // get the task struct
    task = (void *)bpf_get_current_task();
    if (!task) {
        event->status |= STATUS_NOTASK;
    } else {
        p_task = (void *)deref_ptr(task, config->parent);
        set_event_exit_info(event, task, p_task, config);
        set_event_arg_info(event, task, p_task, config, cpu_id);
    }

    check_and_send_event((void *)ctx, event, config);

    // Cleanup
    bpf_map_delete_elem(&args_hash, &pid_tid);

    return 0;
}

