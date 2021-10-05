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
// sysmonGenericEntry_tp.c
//
// Syscall entry programs, one for each of 0 arguments up to 6
// arguments. The purpose is that these generic entry programs can be
// attached to any syscall entry tracepoint, as long as the number of
// arguments matches correctly. The maximum number of arguments a
// syscall can take is 6.
//
//====================================================================

#include "sysmonEBPF_common.h"
#include <sysinternalsEBPF_helpers.c>


// sys_enter for 0 arguments
SEC("sysmon/generic/enter0")
__attribute__((flatten))
int genericEnter0(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint64_t cpuId = bpf_get_smp_processor_id();
    argsStruct *eventArgs;
    uint32_t syscall = args->__syscall_nr;
    uint32_t configId = 0;
    const ebpfConfig *config;

    // retrieve config
    config = bpf_map_lookup_elem(&configMap, &configId);
    if (!config)
        return 0;

    // retrieve map storage for event
    eventArgs = bpf_map_lookup_elem(&argsStorageMap, &cpuId);
    if (!eventArgs)
        return 0;

    if (!sysEnterCheckAndInit(eventArgs, config, syscall, pidTid))
        return 0;

    sysEnterCompleteAndStore(eventArgs, syscall, pidTid);
    return 0;
}

// sys_enter for 1 argument
SEC("sysmon/generic/enter1")
__attribute__((flatten))
int genericEnter1(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint64_t cpuId = bpf_get_smp_processor_id();
    argsStruct *eventArgs;
    uint32_t syscall = args->__syscall_nr;
    uint32_t configId = 0;
    const ebpfConfig *config;

    // retrieve config
    config = bpf_map_lookup_elem(&configMap, &configId);
    if (!config)
        return 0;

    // retrieve map storage for event
    eventArgs = bpf_map_lookup_elem(&argsStorageMap, &cpuId);
    if (!eventArgs)
        return 0;

    if (!sysEnterCheckAndInit(eventArgs, config, syscall, pidTid))
        return 0;

    eventArgs->a[0] = args->a[0];

    sysEnterCompleteAndStore(eventArgs, syscall, pidTid);
    return 0;
}

// sys_enter for 2 arguments
SEC("sysmon/generic/enter2")
__attribute__((flatten))
int genericEnter2(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint64_t cpuId = bpf_get_smp_processor_id();
    argsStruct *eventArgs;
    uint32_t syscall = args->__syscall_nr;
    uint32_t configId = 0;
    const ebpfConfig *config;

    // retrieve config
    config = bpf_map_lookup_elem(&configMap, &configId);
    if (!config)
        return 0;

    // retrieve map storage for event
    eventArgs = bpf_map_lookup_elem(&argsStorageMap, &cpuId);
    if (!eventArgs)
        return 0;

    if (!sysEnterCheckAndInit(eventArgs, config, syscall, pidTid))
        return 0;

    eventArgs->a[0] = args->a[0];
    eventArgs->a[1] = args->a[1];

    sysEnterCompleteAndStore(eventArgs, syscall, pidTid);
    return 0;
}

// sys_enter for 3 arguments
SEC("sysmon/generic/enter3")
__attribute__((flatten))
int genericEnter3(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint64_t cpuId = bpf_get_smp_processor_id();
    argsStruct *eventArgs;
    uint32_t syscall = args->__syscall_nr;
    uint32_t configId = 0;
    const ebpfConfig *config;

    // retrieve config
    config = bpf_map_lookup_elem(&configMap, &configId);
    if (!config)
        return 0;

    // retrieve map storage for event
    eventArgs = bpf_map_lookup_elem(&argsStorageMap, &cpuId);
    if (!eventArgs)
        return 0;

    if (!sysEnterCheckAndInit(eventArgs, config, syscall, pidTid))
        return 0;

    eventArgs->a[0] = args->a[0];
    eventArgs->a[1] = args->a[1];
    eventArgs->a[2] = args->a[2];

    sysEnterCompleteAndStore(eventArgs, syscall, pidTid);
    return 0;
}

// sys_enter for 4 arguments
SEC("sysmon/generic/enter4")
__attribute__((flatten))
int genericEnter4(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint64_t cpuId = bpf_get_smp_processor_id();
    argsStruct *eventArgs;
    uint32_t syscall = args->__syscall_nr;
    uint32_t configId = 0;
    const ebpfConfig *config;

    // retrieve config
    config = bpf_map_lookup_elem(&configMap, &configId);
    if (!config)
        return 0;

    // retrieve map storage for event
    eventArgs = bpf_map_lookup_elem(&argsStorageMap, &cpuId);
    if (!eventArgs)
        return 0;

    if (!sysEnterCheckAndInit(eventArgs, config, syscall, pidTid))
        return 0;

    eventArgs->a[0] = args->a[0];
    eventArgs->a[1] = args->a[1];
    eventArgs->a[2] = args->a[2];
    eventArgs->a[3] = args->a[3];

    sysEnterCompleteAndStore(eventArgs, syscall, pidTid);
    return 0;
}

// sys_enter for 5 arguments
SEC("sysmon/generic/enter5")
__attribute__((flatten))
int genericEnter5(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint64_t cpuId = bpf_get_smp_processor_id();
    argsStruct *eventArgs;
    uint32_t syscall = args->__syscall_nr;
    uint32_t configId = 0;
    const ebpfConfig *config;

    // retrieve config
    config = bpf_map_lookup_elem(&configMap, &configId);
    if (!config)
        return 0;

    // retrieve map storage for event
    eventArgs = bpf_map_lookup_elem(&argsStorageMap, &cpuId);
    if (!eventArgs)
        return 0;

    if (!sysEnterCheckAndInit(eventArgs, config, syscall, pidTid))
        return 0;

    eventArgs->a[0] = args->a[0];
    eventArgs->a[1] = args->a[1];
    eventArgs->a[2] = args->a[2];
    eventArgs->a[3] = args->a[3];
    eventArgs->a[4] = args->a[4];

    sysEnterCompleteAndStore(eventArgs, syscall, pidTid);
    return 0;
}

// sys_enter for 6 arguments
SEC("sysmon/generic/enter6")
__attribute__((flatten))
int genericEnter6(struct tracepoint__syscalls__sys_enter *args)
{
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint64_t cpuId = bpf_get_smp_processor_id();
    argsStruct *eventArgs;
    uint32_t syscall = args->__syscall_nr;
    uint32_t configId = 0;
    const ebpfConfig *config;

    // retrieve config
    config = bpf_map_lookup_elem(&configMap, &configId);
    if (!config)
        return 0;

    // retrieve map storage for event
    eventArgs = bpf_map_lookup_elem(&argsStorageMap, &cpuId);
    if (!eventArgs)
        return 0;

    if (!sysEnterCheckAndInit(eventArgs, config, syscall, pidTid))
        return 0;

    eventArgs->a[0] = args->a[0];
    eventArgs->a[1] = args->a[1];
    eventArgs->a[2] = args->a[2];
    eventArgs->a[3] = args->a[3];
    eventArgs->a[4] = args->a[4];
    eventArgs->a[5] = args->a[5];

    sysEnterCompleteAndStore(eventArgs, syscall, pidTid);
    return 0;
}

