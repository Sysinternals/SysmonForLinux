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
// sysmonFileCreate.c
//
// Reports files created with creat() syscall.
//
//====================================================================

__attribute__((always_inline))
static inline char* set_fileCreate_ext(
    PSYSMON_FILE_CREATE event,
    const ebpfConfig *config,
    const argsStruct *eventArgs,
    const void *task
    )
{
    char *ptr = NULL;
    char *ptr2 = NULL;
    uint64_t extLen = 0;
    uint64_t pathLen = 0;
    char pathFirst = 0x00;
    int ret;
    const void *cred = NULL;

    ptr = (char *)(event + 1);
    memset(event->m_Extensions, 0, sizeof(event->m_Extensions));

    // Insert the UID as the SID
    cred = (const void *)derefPtr(task, config->offsets.cred);
    if (cred) {
        *(uint64_t *)ptr = derefPtr(cred, config->offsets.cred_uid) & 0xFFFFFFFF;
        event->m_Extensions[FC_Sid] = sizeof(uint64_t);
        ptr += sizeof(uint64_t);
    }

    extLen = derefFilepathInto(ptr, task, config->offsets.exe_path, config);
    event->m_Extensions[FC_ImagePath] = extLen;
    extLen &= (PATH_MAX -1);
    ptr += extLen;

    extLen = resolveFdPath(ptr, eventArgs->returnCode, task, config);

    event->m_Extensions[FC_FileName] = extLen;
    ptr += (extLen & (PATH_MAX - 1));

    return ptr;
}

__attribute__((always_inline))
static inline char* set_FileCreate_info(
    PSYSMON_EVENT_HEADER eventHdr,
    const ebpfConfig *config,
    uint64_t pidTid,
    uint32_t cpuId,
    const argsStruct *eventArgs
    )
{
    const void *task = NULL;

    if (eventHdr == NULL || config == NULL || eventArgs == NULL)
        return (char *)eventHdr;

    // only record successful actions
    if (eventArgs->returnCode == -1)
        return (char *)eventHdr;

    // get the task struct
    task = (void *)bpf_get_current_task();
    if (!task)
        return (char *)eventHdr;

    // initialise event
    eventHdr->m_FieldFiltered = 0;
    eventHdr->m_PreFiltered = 0;
    eventHdr->m_SequenceNumber = 0;
    eventHdr->m_SessionId = 0;

    eventHdr->m_EventType = FileCreate;
    PSYSMON_FILE_CREATE event = &eventHdr->m_EventBody.m_FileCreateEvent;

    // set the pid
    event->m_ProcessId = pidTid >> 32;

    // set file create time - this is in nanoseconds and we want 100ns intervals
    event->m_CreateTime.QuadPart = (bpf_ktime_get_ns() + config->bootNsSinceEpoch) / 100;
    event->m_EventTime.QuadPart = event->m_CreateTime.QuadPart;

    // set hash
    event->m_hashType = 0;
    event->m_filehash[0] = 0x00;

    return set_fileCreate_ext(event, config, eventArgs, task);
}

