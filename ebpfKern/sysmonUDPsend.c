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
// sysmonUDPsend.c
//
// Monitor outbound packets and report UDP packets that haven't been
// reported recently.
//
//====================================================================

#include "sysmonEBPF_common.h"
#include <sysinternalsEBPF_helpers.c>
#include "sysmonHelpers.c"

struct tracepoint__skb_consume_skb {
    __uint64_t  pad;
    const void * skbaddr;
};

// network connection state change
SEC("sysmon/consume_skb")
__attribute__((flatten))
int UDPsend(struct tracepoint__skb_consume_skb *args)
{
    uint64_t pidTid;
    uint32_t cpuId = bpf_get_smp_processor_id();
    PSYSMON_EVENT_HEADER eventHdr = NULL;
    const ebpfConfig *config;
    char *ptr = NULL;
    const void *task = NULL;
    uint64_t extLen = 0;
    uint32_t pid = 0;
    unsigned char *data = NULL;
    void *dataAddr = NULL;
    uint16_t networkHeader = 0;
    uint16_t frameType = 0;
    uint16_t plen = 0;
    uint16_t headerSize = 0;
    uint64_t index1 = 0; 
    uint64_t index2 = 0; 
    packetAddrs *p = NULL;
    packetAddrs pAddrs;
    LONGLONG *lastTimeAddr = NULL;
    LONGLONG lastTime = 0;
    LONGLONG curTime = 0;
    bool IPv4 = true;

    if (!getConfig(&config, &pidTid))
        return 0;

    // get the task struct
    task = (const void *)bpf_get_current_task();
    if (!task)
        return 0;

    // get address of packet data from skbaddr
    if (bpf_probe_read(&dataAddr, sizeof(dataAddr), args->skbaddr + config->offsets.skb_data[0]) < 0)
        return 0;

    if (bpf_probe_read(&networkHeader, sizeof(networkHeader), args->skbaddr + config->offsets.skb_network_header[0]) < 0)
        return 0;

    // get packet data buffer
    data = bpf_map_lookup_elem(&packetStorageMap, &cpuId);
    if (data == NULL)
        return 0;

    // read frame header including packet length in IPv4, and packet length and next header ID in IPv6
    memset(data, 0, PACKET_SIZE);
    if (bpf_probe_read(data, (networkHeader + 5) & PACKET_MASK, dataAddr) < 0)
        return 0;

    // check for IP
    frameType = (data[12] << 8) | data[13];
    if (frameType == PROTO_IPV4) {
        IPv4 = true;
        headerSize = (data[(networkHeader-2) & PACKET_MASK] & 0xF) * 4;
        plen = (data[networkHeader & PACKET_MASK] << 8) | data[(networkHeader+1) & PACKET_MASK];
    } else if (frameType == PROTO_IPV6) {
        if (data[(networkHeader+4) & PACKET_MASK] != PROTO_UDP)
            // TODO: handle IPv6 extension headers
            return 0;
        IPv4 = false;
        headerSize = 40;
        plen = (data[(networkHeader+2) & PACKET_MASK] << 8) | data[(networkHeader+3) & PACKET_MASK];
        plen += 40; // IPv6 header len
    } else
        return 0;

    // read packet
    if (plen > PACKET_MASK) {
        if (bpf_probe_read(data, PACKET_SIZE, dataAddr + 14) < 0)
            return 0;
    } else {
        if (bpf_probe_read(data, plen & PACKET_MASK, dataAddr + 14) < 0)
            return 0;
    }

    if (IPv4 && data[9] != PROTO_UDP)
        return 0;

    // get packet addresses buffer
    p = &pAddrs;
    memset(p, 0, sizeof(pAddrs));

    p->IPv4 = IPv4;

    index1 = headerSize;
    index2 = headerSize + 1;
    //
    // This asm volatile is necessary to force the '&=' on the variables
    // because otherwise clang optimises them out causing the verifier to
    // complain.
    //
    asm volatile("%[index1] &= " XSTR(PACKET_SIZE - 1) "\n"
                 "%[index2] &= " XSTR(PACKET_SIZE - 1) "\n"
                 :[index1]"+&r"(index1), [index2]"+&r"(index2)
                 );

    p->srcPort = ((uint16_t)(data[index1]) << 8) | data[index2];

    index1 = headerSize + 2;
    index2 = headerSize + 3;
    asm volatile("%[index1] &= " XSTR(PACKET_SIZE - 1) "\n"
                 "%[index2] &= " XSTR(PACKET_SIZE - 1) "\n"
                 :[index1]"+&r"(index1), [index2]"+&r"(index2)
                 );

    p->dstPort = ((uint16_t)(data[index1]) << 8) | data[index2];

    if (IPv4) {
        memset(p->srcAddr, 0, sizeof(p->srcAddr));
        memset(p->dstAddr, 0, sizeof(p->srcAddr));
        memcpy(p->srcAddr, &data[12], 4);
        memcpy(p->dstAddr, &data[16], 4);
    } else {
        memcpy(p->srcAddr, &data[8], 16);
        memcpy(p->dstAddr, &data[24], 16);
    }

    lastTimeAddr = (LONGLONG *)bpf_map_lookup_elem(&UDPsendAge, p);
    if (lastTimeAddr == NULL) {
        lastTime = -1;
    } else {
        lastTime = *lastTimeAddr;
    }

    // get the current time
    curTime = (bpf_ktime_get_ns() + config->bootNsSinceEpoch) / 100;

    if (lastTime != -1) {
        // exists in hash

        // only act on packet addresses we haven't seen or ones we haven't seen lately
        if (curTime - lastTime < UDP_REPORT_INTERVAL)
            return 0;
    }

    // insert/update the hash
    bpf_map_update_elem(&UDPsendAge, p, &curTime, BPF_ANY);

    if (!getEventHdr(&eventHdr, cpuId))
        return 0;

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
    event->m_SockId = 0;

    event->m_AddrIsIPv4 = p->IPv4;
    event->m_SrcPort = p->srcPort;
    event->m_DstPort = p->dstPort;
    memcpy(event->m_SrcAddr, p->srcAddr, sizeof(p->srcAddr));
    memcpy(event->m_DstAddr, p->dstAddr, sizeof(p->dstAddr));

    ptr = (char *)(event + 1);
    eventHdr->m_EventSize = (uint32_t)((void *)ptr - (void *)eventHdr);
    checkAndSendEvent((void *)args, eventHdr, config);

    return 0;
}


