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
// sysmonProcAccessed.c
//
// Report use of ptrace().
//
//====================================================================

#include <linux/ptrace.h>

__attribute__((always_inline))
static inline char* set_ProcAccessed_info(
    PSYSMON_EVENT_HEADER eventHdr,
    const ebpfConfig *config,
    uint64_t pidTid,
    uint32_t cpuId,
    const argsStruct *eventArgs
    )
{
    const void *task = NULL;
    char *ptr = NULL;
    uint64_t extLen = 0;
    const void *cred = NULL;

    if (eventHdr == NULL || config == NULL || eventArgs == NULL)
        return (char *)eventHdr;

    // only record successful actions
    if (eventArgs->returnCode != 0)
        return (char *)eventHdr;

    // only record PTRACE_ATTACH and PTRACE_SEIZE events
    if (eventArgs->a[0] != PTRACE_ATTACH && eventArgs->a[0] != PTRACE_SEIZE)
        return (char *)eventHdr;

    // get the task struct
    task = (const void *)bpf_get_current_task();
    if (!task)
        return (char *)eventHdr;

    // initialise event
    eventHdr->m_FieldFiltered = 0;
    eventHdr->m_PreFiltered = 0;
    eventHdr->m_SequenceNumber = 0;
    eventHdr->m_SessionId = 0;

    eventHdr->m_EventType = ProcessAccess;
    PSYSMON_PROCESS_ACCESS event = (PSYSMON_PROCESS_ACCESS)&eventHdr->m_EventBody.m_ProcessAccessEvent;

    // set the pid and tid
    event->m_ClientProcessID = pidTid >> 32;
    event->m_ClientThreadID = pidTid & (0xFFFFFFFF);

    // set event time - this is in nanoseconds and we want 100ns intervals
    event->m_EventSystemTime.QuadPart = (bpf_ktime_get_ns() + config->bootNsSinceEpoch) / 100;

    // set target pid
    event->m_TargetPid = eventArgs->a[1];

    // we don't use GrantedAccess
    event->m_GrantedAccess = 0;

    ptr = (char *)(event + 1);
    memset(event->m_Extensions, 0, sizeof(event->m_Extensions));
    extLen = derefFilepathInto(ptr, task, config->offsets.exe_path, config);
    event->m_Extensions[PA_ClientImage] = extLen;
    ptr += (extLen & (PATH_MAX - 1));

    // Insert the UID as the SID
    cred = (const void *)derefPtr(task, config->offsets.cred);
    if (cred) {
        *(uint64_t *)ptr = derefPtr(cred, config->offsets.cred_uid) & 0xFFFFFFFF;
        event->m_Extensions[PA_SidSource] = sizeof(uint64_t);
        ptr += sizeof(uint64_t);
    }

    return ptr;
}

