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
// sysmonFileOpen.c
//
// Report files created with open()/openat(), plus block devices
// accessed.
//
//====================================================================

__attribute__((always_inline))
static inline char* set_FileOpen_info(
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
    const void *inode = NULL;
    uint64_t eventTimeNs = 0;
    uint64_t fileTimeNs = 0;
    uint64_t timeDiffNs = 0;
    const void *cred = NULL;

    if (eventHdr == NULL || config == NULL || eventArgs == NULL)
        return (char *)eventHdr;

    // only record successful actions
    if (eventArgs->returnCode == -1)
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

    eventHdr->m_EventType = LinuxFileOpen;
    PSYSMON_LINUX_FILE_OPEN event = (PSYSMON_LINUX_FILE_OPEN)&eventHdr->m_EventBody.m_FileCreateEvent;

    // set the pid
    event->m_ProcessId = pidTid >> 32;

    // set event time - this is in nanoseconds and we want 100ns intervals
    event->m_EventTime.QuadPart = (bpf_ktime_get_ns() + config->bootNsSinceEpoch) / 100;
    // store event time in nanoseconds for comparison
    eventTimeNs = bpf_ktime_get_ns() + config->bootNsSinceEpoch;

    if (eventArgs->syscallId == __NR_open) {
        event->m_Flags = (uint32_t)eventArgs->a[1];
    } else {
        event->m_Flags = (uint32_t)eventArgs->a[2];
    }

    ptr = (char *)(event + 1);
    memset(event->m_Extensions, 0, sizeof(event->m_Extensions));

    // Insert the UID as the SID
    cred = (const void *)derefPtr(task, config->offsets.cred);
    if (cred) {
        *(uint64_t *)ptr = derefPtr(cred, config->offsets.cred_uid) & 0xFFFFFFFF;
        event->m_Extensions[LINUX_FO_Sid] = sizeof(uint64_t);
        ptr += sizeof(uint64_t);
    }

    extLen = derefFilepathInto(ptr, task, config->offsets.exe_path, config);
    event->m_Extensions[LINUX_FO_ImagePath] = extLen;
    extLen &= (MAX_PATH -1);
    ptr += extLen;

    event->m_atime.tv_sec = 0;
    event->m_atime.tv_nsec = 0;
    event->m_mtime.tv_sec = 0;
    event->m_mtime.tv_nsec = 0;
    event->m_ctime.tv_sec = 0;
    event->m_ctime.tv_nsec = 0;
    event->m_Mode = 0;
    timeDiffNs = 0;
    inode = derefInodeFromFd(task, eventArgs->returnCode, config);
    if (inode) {
        bpf_probe_read(&event->m_atime, sizeof(event->m_atime), inode + config->offsets.inode_atime[0]);
        bpf_probe_read(&event->m_mtime, sizeof(event->m_mtime), inode + config->offsets.inode_mtime[0]);
        bpf_probe_read(&event->m_ctime, sizeof(event->m_ctime), inode + config->offsets.inode_ctime[0]);
        bpf_probe_read(&event->m_Mode, sizeof(event->m_Mode), inode + config->offsets.inode_mode[0]);

        fileTimeNs = (event->m_atime.tv_sec * 1000 * 1000 * 1000) + event->m_atime.tv_nsec;
        if (fileTimeNs > eventTimeNs) {
            timeDiffNs = fileTimeNs - eventTimeNs;
        } else {
            timeDiffNs = eventTimeNs - fileTimeNs;
        }
    }

    if ((event->m_Flags & O_CREAT                           // object is created
        && (event->m_Mode & S_IFMT) == S_IFREG              // and is a regular file
        && event->m_atime.tv_sec == event->m_mtime.tv_sec   // and all the file times are equal
        && event->m_mtime.tv_sec == event->m_ctime.tv_sec
        && event->m_atime.tv_nsec == event->m_mtime.tv_nsec
        && event->m_mtime.tv_nsec == event->m_ctime.tv_nsec
        && timeDiffNs < (100 * 1000 * 1000)                 // and file times are within 100ms of event time
        && config->active[__NR_CREATE] )
        ||
        ((event->m_Mode & S_IFMT) == S_IFBLK                 // or object is a block device
        && config->active[__NR_RAWACCESS] ) )
    {
        extLen = resolveFdPath(ptr, eventArgs->returnCode, task, config);

        event->m_Extensions[LINUX_FO_PathName] = extLen;
        ptr += (extLen & (PATH_MAX - 1));

        return ptr;
    } else {
        // this not a file open nor access to a block device, so we're not interested
        // in it. Not sending this back will reduce load on the ring buffer
        return (char *)eventHdr;
    }
}

