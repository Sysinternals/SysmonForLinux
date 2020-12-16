/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <unistd.h>
#include <asm/unistd.h>
#include <stdlib.h>
#include <libbpf.h>
#include <sys/resource.h>
#include <bpf.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/utsname.h>
#include <types.h>
#include <signal.h>

void ebpf_telemetry_close_all();
int ebpf_telemetry_start(char *sysconf_filename, void (*event_cb)(void *ctx, int cpu, void *data, __u32 size), void (*events_lost_cb)(void *ctx, int cpu, __u64 lost_cnt));

