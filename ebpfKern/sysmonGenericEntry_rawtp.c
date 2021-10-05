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

//====================================================================
//
// sysmonGenericEntry_rawtp.c
//
// Raw syscall entry program.
//
//====================================================================

#include "sysmonEBPF_common.h"
#include <sysinternalsEBPF_helpers.c>


// store the syscall arguments from the registers in the event
__attribute__((always_inline))
static inline bool set_eventArgs(unsigned long *a, const struct pt_regs *regs)
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

 
SEC("sysmon/generic/rawEnter")
__attribute__((flatten))
int genericRawEnter(struct bpf_our_raw_tracepoint_args *ctx)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint32_t cpuId = bpf_get_smp_processor_id();
    argsStruct *eventArgs;
    uint32_t syscall = ctx->args[1];
    uint32_t configId = 0;
    const ebpfConfig *config;
    const void *task;

    // retrieve config
    config = bpf_map_lookup_elem(&configMap, &configId);
    if (!config) {
        return 0;
    }

    // bail early for syscalls we aren't interested in
    if (!config->active[syscall & (SYSCALL_ARRAY_SIZE - 1)]) {
        return 0;
    }

    // retrieve map storage for event
    eventArgs = bpf_map_lookup_elem(&argsStorageMap, &cpuId);
    if (!eventArgs) {
        return 0;
    }

    if (!sysEnterCheckAndInit(eventArgs, config, syscall, pidTid)) {
        return 0;
    }

    // retrieve the register state
    const struct pt_regs *regs = (const struct pt_regs *)ctx->args[0];

    if (!set_eventArgs(eventArgs->a, regs)) {
        BPF_PRINTK("set_eventArgs failed\n");
    }
    sysEnterCompleteAndStore(eventArgs, syscall, pidTid);
    return 0;
}

