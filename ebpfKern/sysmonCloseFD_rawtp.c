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

#include "sysmonEBPF_common.h"
#include <sysinternalsEBPF_helpers.c>
#include "sysmonHelpers.c"
#include "sysmonCloseFD.c"

SEC("sysmon/CloseFD/rawExit")
__attribute__((flatten))
int CloseFDRawExit(struct bpf_our_raw_tracepoint_args *ctx)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    argsStruct *eventArgs = NULL;
    const struct pt_regs *regs = (const struct pt_regs *)ctx->args[0];
    const ebpfConfig *config;
    
    if (!setUpEvent(&config, &eventArgs))
        return 0;

    // only handle close events
    if (eventArgs->syscallId != __NR_close) {
        return 0;
    }

    // set the return code
    if (bpf_probe_read(&eventArgs->returnCode, sizeof(int64_t), (void *)&SYSCALL_PT_REGS_RC(regs)) != 0){
        BPF_PRINTK("ERROR, failed to get return code\n");
    }

    set_CloseFD_info(pidTid, eventArgs);

    // Cleanup hash as we handled this event
    bpf_map_delete_elem(&argsHash, &pidTid);

    return 0;
}

