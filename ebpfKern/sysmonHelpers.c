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
// sysmonHelpers.c
//
// Inline helper functions for Sysmon's eBPF programs.
//
//====================================================================

#ifndef SYSMON_HELPERS_C
#define SYSMON_HELPERS_C

// Sysmon-specific inline helper functions

//--------------------------------------------------------------------
//
// getConfig
//
// Obtain the PID/TID and retrieve the config. Check that the PID
// isn't the same as the Sysmon process.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline bool getConfig(const ebpfConfig **config, uint64_t *pidTid)
{
    uint32_t configId = 0;

    *pidTid = bpf_get_current_pid_tgid();

    // retrieve config
    *config = bpf_map_lookup_elem(&configMap, &configId);
    if (*config == NULL) {
        return false;
    }

    // don't report any syscalls for the userland PID
    if (((*pidTid) >> 32) == (*config)->userlandPid) {
        return false;
    }

    return true;
}

//--------------------------------------------------------------------
//
// setUpEvent
//
// Get the config and retrieve the stored syscall arguments.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline bool setUpEvent(const ebpfConfig **config, argsStruct **eventArgs)
{
    uint64_t pidTid = 0;

    if (!getConfig(config, &pidTid)) {
        return false;
    }

    // retrieve map storage for event args
    // this was created on the preceding sys_enter
    // if the pidTid is in our map then we must have stored it
    *eventArgs = bpf_map_lookup_elem(&argsHash, &pidTid);
    if (*eventArgs == NULL) {
        return false;
    }

    return true;
}

//--------------------------------------------------------------------
//
// getEventHdr
//
// Locate the temporary storage for the event as we build it.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline bool getEventHdr(PSYSMON_EVENT_HEADER *eventHdr, uint32_t cpuId)
{
    // retrieve map storage for event
    *eventHdr = bpf_map_lookup_elem(&eventStorageMap, &cpuId);
    if (!*eventHdr) {
        return false;
    }

    return true;
}

//--------------------------------------------------------------------
//
// checkAndSendEvent
//
// Check the size of the event is within limits, then send it.
// Note, eventOutput monitors for perf ring buffer errors and records
// them in the perf error map.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline void checkAndSendEvent(void *ctx, const PSYSMON_EVENT_HEADER eventHdr, const ebpfConfig *config)
{
    size_t size = eventHdr->m_EventSize;
    eventOutput(ctx, &eventMap, BPF_F_CURRENT_CPU, eventHdr, size < LINUX_MAX_EVENT_SIZE ? size : 0);
}

//--------------------------------------------------------------------
//
// checkAndSendEventNoError
//
// Check the size of the event is within limits, then send it directly
// without going through the error handler.
//
//--------------------------------------------------------------------
__attribute__((always_inline))
static inline void checkAndSendEventNoError(void *ctx, const PSYSMON_EVENT_HEADER eventHdr, const ebpfConfig *config)
{
    size_t size = eventHdr->m_EventSize;
    bpf_perf_event_output(ctx, &eventMap, BPF_F_CURRENT_CPU, eventHdr, size < LINUX_MAX_EVENT_SIZE ? size : 0);
}
 
#endif
