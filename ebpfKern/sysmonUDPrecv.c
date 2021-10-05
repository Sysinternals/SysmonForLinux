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
// sysmonUDPrecv.c
//
// Report successful calls to read()/recv()/recvmsg()/recvmmsg()
// where the FD is a socket and it hasn't been reported recently.
// This is used to identify UDP packets being received.
//
//====================================================================

__attribute__((always_inline))
static inline char* set_UDPrecv_info(
    PSYSMON_EVENT_HEADER eventHdr,
    const ebpfConfig *config,
    uint64_t pidTid,
    uint32_t cpuId,
    const argsStruct *eventArgs
    )
{
    const void *task = NULL;
    char *ptr = NULL;
    const void *inode = NULL;
    uint32_t mode = 0;
    uint64_t pidFd = 0;
    LONGLONG *lastTimeAddr = NULL;
    LONGLONG lastTime = 0;
    LONGLONG curTime = 0;
    struct sockaddr_in s_addr;
    struct sockaddr_in6 s_addr6;
    uint32_t socklen;

    if (eventHdr == NULL || config == NULL || eventArgs == NULL)
        return (char *)eventHdr;

    // only record successful actions
    if (eventArgs->returnCode == -1)
        return (char *)eventHdr;

    // get the task struct
    task = (const void *)bpf_get_current_task();
    if (!task)
        return (char *)eventHdr;

    // get the last time we saw this (0 == TCP)
    pidFd = (pidTid & 0xFFFFFFFF00000000) | (eventArgs->a[0] & 0xFFFFFFFF);
    lastTimeAddr = (LONGLONG *)bpf_map_lookup_elem(&UDPrecvAge, &pidFd);
    if (lastTimeAddr == NULL) {
        lastTime = -1;
    } else {
        lastTime = *lastTimeAddr;
    }

    if (lastTime == 0)
        // TCP FD
        return (char *)eventHdr;

    // get the current time
    curTime = (bpf_ktime_get_ns() + config->bootNsSinceEpoch) / 100;

    if (lastTime == -1) {
        // Not in hash

        inode = derefInodeFromFd(task, eventArgs->a[0], config);

        // a valid call must have a valid inode
        if (inode == NULL)
            return (char *)eventHdr;

        bpf_probe_read(&mode, sizeof(mode), inode + config->offsets.inode_mode[0]);

        // and a socket action must be on a socket
        if ((mode & S_IFMT) != S_IFSOCK)
            return (char *)eventHdr;

    } else {
        // exists in hash

        // only act on sockets we haven't seen or ones we haven't seen lately
        if (curTime - lastTime < UDP_REPORT_INTERVAL)
            return (char *)eventHdr;
    }

    // insert/update the hash
    bpf_map_update_elem(&UDPrecvAge, &pidFd, &curTime, BPF_ANY);

    // initialise event
    eventHdr->m_FieldFiltered = 0;
    eventHdr->m_PreFiltered = 0;
    eventHdr->m_SequenceNumber = 0;
    eventHdr->m_SessionId = 0;

    eventHdr->m_EventType = LinuxNetworkEvent;
    PSYSMON_LINUX_NETWORK_EVENT event = (PSYSMON_LINUX_NETWORK_EVENT)&eventHdr->m_EventBody;

    event->m_ProcessId = pidTid >> 32;
    event->m_EventTime.QuadPart = curTime;

    event->m_IsTCP = false;
    event->m_SockId = (const void *)(eventArgs->a[0] & 0xFFFFFFFF);

    memset(event->m_SrcAddr, 0, sizeof(event->m_SrcAddr));
    memset(event->m_DstAddr, 0, sizeof(event->m_DstAddr));
    event->m_SrcPort = 0;
    event->m_DstPort = 0;

    ptr = (char *)(event + 1);

    return ptr;
}

