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
// sysmonTCPaccept.c
//
// Report successful accept() calls for inbound network connections.
//
//====================================================================

__attribute__((always_inline))
static inline const char* set_TCPaccept_info(
    PSYSMON_EVENT_HEADER eventHdr,
    const ebpfConfig *config,
    uint64_t pidTid,
    uint32_t cpuId,
    const argsStruct *eventArgs
    )
{
    const void *task = NULL;
    const char *ptr = NULL;
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

    // initialise event
    eventHdr->m_FieldFiltered = 0;
    eventHdr->m_PreFiltered = 0;
    eventHdr->m_SequenceNumber = 0;
    eventHdr->m_SessionId = 0;

    eventHdr->m_EventType = LinuxNetworkEvent;
    PSYSMON_LINUX_NETWORK_EVENT event = (PSYSMON_LINUX_NETWORK_EVENT)&eventHdr->m_EventBody;

    // set the pid
    event->m_ProcessId = pidTid >> 32;

    // set event time - this is in nanoseconds and we want 100ns intervals
    event->m_EventTime.QuadPart = (bpf_ktime_get_ns() + config->bootNsSinceEpoch) / 100;

    event->m_IsTCP = true;
    event->m_OldState = TCP_LISTEN;
    event->m_NewState = TCP_ESTABLISHED;
    event->m_DstPort = 0;
    event->m_SockId = (void *)eventArgs->returnCode;

    memset(event->m_SrcAddr, 0, sizeof(event->m_SrcAddr));
    memset(event->m_DstAddr, 0, sizeof(event->m_DstAddr));

    ptr = (const char *)(event + 1);

    bpf_probe_read(&socklen, sizeof(socklen), (void *)eventArgs->a[2]);

    if (socklen <= sizeof(struct sockaddr_in)) {
        bpf_probe_read(&s_addr, sizeof(s_addr), (void *)eventArgs->a[1]);
        event->m_AddrIsIPv4 = true;
        bpf_probe_read(event->m_SrcAddr, 4, (void *)&(s_addr.sin_addr));
        event->m_SrcPort = (s_addr.sin_port >> 8) | ((s_addr.sin_port & 0xFF) << 8);
    } else {
        bpf_probe_read(&s_addr6, sizeof(s_addr6), (void *)eventArgs->a[1]);
        event->m_AddrIsIPv4 = false;
        bpf_probe_read(event->m_SrcAddr, 16, (void *)&(s_addr6.sin6_addr));
        event->m_SrcPort = (s_addr6.sin6_port >> 8) | ((s_addr6.sin6_port & 0xFF) << 8);
    }

    return ptr;
}

