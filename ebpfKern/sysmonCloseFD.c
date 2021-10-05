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
// sysmonCloseFD.c
//
// Removes PID/FD entry from inbound UDP tracking map.
//
//====================================================================

__attribute__((always_inline))
static inline void set_CloseFD_info(
    uint64_t pidTid,
    const argsStruct *eventArgs
    )
{
    uint64_t pidFd = 0;

    if (eventArgs == NULL)
        return;

    // only record successful actions
    if (eventArgs->returnCode != 0)
        return;

    pidFd = (pidTid & 0xFFFFFFFF00000000) | (eventArgs->a[0] & 0xFFFFFFFF);
    bpf_map_delete_elem(&UDPrecvAge, &pidFd);
}

