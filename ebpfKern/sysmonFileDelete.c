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
// sysmonFileDelete.c
//
// Reports files deleted.
//
//====================================================================

__attribute__((always_inline))
static inline char* set_FileDelete_info(
    PSYSMON_EVENT_HEADER eventHdr,
    const ebpfConfig *config,
    uint64_t pidTid,
    uint32_t cpuId,
    const argsStruct *eventArgs
    )
{
    const void *task = NULL;
    const void *cred = NULL;
    char *ptr = NULL;
    char *ptr2 = NULL;
    const void *path_addr = NULL;
    bool relative = false;
    uint64_t extLen = 0;
    uint64_t pathLen = 0;
    char pathFirst = 0x00;

    if (eventHdr == NULL || config == NULL || eventArgs == NULL)
        return (char *)eventHdr;

    // only record successful actions
    if (eventArgs->returnCode != 0)
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

    eventHdr->m_EventType = FileDelete;
    PSYSMON_FILE_DELETE event = (PSYSMON_FILE_DELETE)&eventHdr->m_EventBody.m_FileDeleteEvent;

    // set the pid
    event->m_ProcessId = pidTid >> 32;

    // set event time - this is in nanoseconds and we want 100ns intervals
    event->m_DeleteTime.QuadPart = (bpf_ktime_get_ns() + config->bootNsSinceEpoch) / 100;

    event->m_HashType = 0;
    event->m_IsExecutable = 0;
    cred = (const void *)derefPtr(task, config->offsets.cred);
    event->m_Archived[0] = 0x00;
    event->m_TrackerId = 0;

    path_addr = (const void *)eventArgs->a[0];

    ptr = (char *)(event + 1);
    memset(event->m_Extensions, 0, sizeof(event->m_Extensions));

    // Insert the UID as the SID
    if (cred) {
        *(uint64_t *)ptr = derefPtr(cred, config->offsets.cred_uid) & 0xFFFFFFFF;
        event->m_Extensions[FD_Sid] = sizeof(uint64_t);
        ptr += sizeof(uint64_t);
    }

    if (bpf_probe_read(&pathFirst, 1, path_addr) < 0)
        return (char *)eventHdr;

    if (pathFirst == '/') {
        relative = false;
    } else {
        relative = true;
    }

    if (relative) {
        // relative to current directory
        extLen = derefFilepathInto(ptr, task, config->offsets.pwd_path, config);
        if (extLen <= 0)
            return (char *)eventHdr;
        extLen &= (PATH_MAX -1);
        ptr[extLen - 1] = '/';
        ptr2 = ptr + extLen;
        pathLen = bpf_probe_read_str(ptr2, PATH_MAX, path_addr);
        if (pathLen < 0)
            return (char *)eventHdr;
        extLen += pathLen;
        event->m_Extensions[FD_FileName] = extLen;
        extLen &= ((PATH_MAX * 2) -1);
        ptr += extLen;
    } else {
        extLen = bpf_probe_read_str(ptr, PATH_MAX, path_addr);
        if (extLen <= 0)
            return (char *)eventHdr;
        event->m_Extensions[FD_FileName] = extLen;
        ptr += (extLen & (PATH_MAX - 1));
    }

    extLen = derefFilepathInto(ptr, task, config->offsets.exe_path, config);
    event->m_Extensions[FD_ImagePath] = extLen;
    extLen &= (MAX_PATH -1);
    ptr += extLen;

    return ptr;
}

