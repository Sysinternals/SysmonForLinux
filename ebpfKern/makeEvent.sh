#!/bin/bash
#
#    SysmonForLinux
#
#    Copyright (c) Microsoft Corporation
#
#    All rights reserved.
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

if [[ "$1" == "" ]]; then
    echo "$0: Make BPF event source code from templates"
    echo "$0 eventName"
    exit 1
fi

EVENT=$1

cat sysmonTEMPLATE.c | sed -e "s/EVENT_NAME/${EVENT}/" > sysmon${EVENT}.c
cat sysmonTEMPLATE_tp.c | sed -e "s/EVENT_NAME/${EVENT}/" > sysmon${EVENT}_tp.c
cat sysmonTEMPLATE_rawtp.c | sed -e "s/EVENT_NAME/${EVENT}/" > sysmon${EVENT}_rawtp.c

