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
// sysmonTCPconnection_5_6_.c
//
// Report TCP state change for kernel v5.6 onwards.
//
//====================================================================

#include "sysmonEBPF_common.h"
#include <sysinternalsEBPF_helpers.c>
#include "sysmonHelpers.c"

struct tracepoint__sock__inet_sock_set_state {
    __uint64_t  pad;
    const void  *skaddr;      // kernel struct sock *
    int         oldstate;     
    int         newstate;     
    __u16       sport;      
    __u16       dport;      
    __u16       family;     
    __u16       protocol;    
    __u8        saddr[4];    
    __u8        daddr[4];    
    __u8        saddr_v6[16];        
    __u8        daddr_v6[16];        
};

typedef enum {
    FAMILY_AF_INET = 2,
    FAMILY_AF_INET6 = 10
} family;

typedef enum {
    PROTO_IPPROTO_TCP = 6,
    PROTO_IPPROTO_DCCP = 33,
    PROTO_IPPROTO_SCTP = 132
} protocol;

// network connection state change
SEC("sysmon/inet_sock_set_state")
__attribute__((flatten))
int TCPconnection(struct tracepoint__sock__inet_sock_set_state *args)
{
    uint64_t pidTid;
    uint32_t cpuId = bpf_get_smp_processor_id();
    PSYSMON_EVENT_HEADER eventHdr = NULL;
    const ebpfConfig *config;
    char *ptr = NULL;
    const void *task = NULL;
    uint64_t extLen = 0;
    uint32_t pid = 0;

    if (!getConfig(&config, &pidTid))
        return 0;

    if (!getEventHdr(&eventHdr, cpuId))
        return 0;

    if (!config->active[__NR_NETWORK])
        return 0;

    // get the task struct
    task = (const void *)bpf_get_current_task();
    if (!task)
        return 0;

    if (!(args->newstate == TCP_SYN_SENT
            || (args->oldstate == TCP_SYN_SENT && args->newstate == TCP_ESTABLISHED)
            || (args->oldstate == TCP_SYN_RECV && args->newstate == TCP_ESTABLISHED)
            || (args->newstate == TCP_CLOSE)))
        // only interested in connections that being initiated, connected or closed
        return 0;

    if (args->family != FAMILY_AF_INET && args->family != FAMILY_AF_INET6)
        // only interested in TCP/IP
        return 0;

    if (args->protocol != PROTO_IPPROTO_TCP)
        // only interested in TCP
        return 0;

    // initialise event
    eventHdr->m_FieldFiltered = 0;
    eventHdr->m_PreFiltered = 0;
    eventHdr->m_SequenceNumber = 0;
    eventHdr->m_SessionId = 0;

    eventHdr->m_EventType = LinuxNetworkEvent;
    PSYSMON_LINUX_NETWORK_EVENT event = (PSYSMON_LINUX_NETWORK_EVENT)&eventHdr->m_EventBody;

    event->m_ProcessId = pidTid >> 32; // this might not match the related process
    event->m_EventTime.QuadPart = (bpf_ktime_get_ns() + config->bootNsSinceEpoch) / 100;

    event->m_IsTCP = true;
    event->m_SockId = args->skaddr;
    event->m_OldState = args->oldstate;
    event->m_NewState = args->newstate;
    event->m_SrcPort = args->sport;
    event->m_DstPort = args->dport;

    memset(event->m_SrcAddr, 0, sizeof(event->m_SrcAddr));
    memset(event->m_DstAddr, 0, sizeof(event->m_DstAddr));

    ptr = (char *)(event + 1);

    if (args->family == FAMILY_AF_INET) {
        event->m_AddrIsIPv4 = true;
        bpf_probe_read(event->m_SrcAddr, sizeof(args->saddr), (void *)args->saddr);
        bpf_probe_read(event->m_DstAddr, sizeof(args->daddr), (void *)args->daddr);
    } else {
        event->m_AddrIsIPv4 = false;
        bpf_probe_read(event->m_SrcAddr, sizeof(args->saddr_v6), (void *)args->saddr_v6);
        bpf_probe_read(event->m_DstAddr, sizeof(args->daddr_v6), (void *)args->daddr_v6);
    }

    eventHdr->m_EventSize = (uint32_t)((void *)ptr - (void *)eventHdr);
    checkAndSendEvent((void *)args, eventHdr, config);

    return 0;
}


