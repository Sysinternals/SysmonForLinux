#!/bin/bash
#
#    SysmonForLinux
#
#    Copyright (c) Microsoft Corporation
#
#    All rights reserved.
#
#    MIT License
#
#    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
#    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
#    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

#################################################################################
#
# extractMsgOp.sh
#
# Extracts defines from sysmonmsgop.man
#
#################################################################################

SYSMONMSGOP=sysmonmsgop.man
if [[ "$1" == "HEADER" ]]; then
    # H file
    echo "// Copyright (c) 2021 Microsoft Corporation."
    echo ""
    echo "#pragma once"
    echo ""
    echo "extern const GUID SYSMON_PROVIDER;"
    echo "#define SYSMON_CHANNEL 0x10"
    echo ""
    grep '<task name' $SYSMONMSGOP | sed -e 's/^.*symbol="\([^"]*\)".*\(..\)}".*$/#define \1 0x\2/'
    echo ""
    grep '<event symbol=' $SYSMONMSGOP | grep "win:Error" | sed -e 's/^.*symbol="\([^"]*\)".*value="\([^"]*\).*version="\([^"]*\)".*$/extern const EVENT_DESCRIPTOR \1;/'
    grep '<event symbol=' $SYSMONMSGOP | grep "win:Informational" | sed -e 's/^.*symbol="\([^"]*\)".*value="\([^"]*\).*version="\([^"]*\)".*$/extern const EVENT_DESCRIPTOR \1;/'
    echo ""
    grep '<event symbol=' $SYSMONMSGOP | grep "win:Error" | sed -e 's/^.*symbol="\([^"]*\)".*value="\([^"]*\).*version="\([^"]*\)".*$/#define \1_value \2/'
    grep '<event symbol=' $SYSMONMSGOP | grep "win:Informational" | sed -e 's/^.*symbol="\([^"]*\)".*value="\([^"]*\).*version="\([^"]*\)".*$/#define \1_value \2/'
    X=`grep '<task name' $SYSMONMSGOP | wc -l`
    echo "#define EVENT_COUNT " $X
    # find next power of 2 for number of events
    X=$((X - 1))
    X=$((X | (X>>1)))
    X=$((X | (X>>2)))
    X=$((X | (X>>4)))
    X=$((X | (X>>8)))
    X=$((X | (X>>16)))
    echo "// EVENT_COUNT_P2 is always the power of 2 equal or greater"
    echo "// than the actual number of events, for easy eBPF maths"
    echo "#define EVENT_COUNT_P2 " $((X + 1))

else
    # C file
    echo "// Copyright (c) 2021 Microsoft Corporation."
    echo ""
    echo '#include "stdafx.h"'
    echo ""
    echo -n "const GUID SYSMON_PROVIDER = "
    echo -n `grep 'SYSMON_PROVIDER' $SYSMONMSGOP | sed -e 's/^.*guid="{\(.\{8\}\)-\(....\)-\(....\)-\(..\)\(..\)-\(..\)\(..\)\(..\)\(..\).*$/{0x\1, 0x\2, 0x\3, {0x\4, 0x\5, 0x\6, 0x\7, 0x\8, 0x\9, /'`
    echo `grep 'SYSMON_PROVIDER' $SYSMONMSGOP | sed -e 's/^.*guid="{.\{8\}-....-....-....-.\{8\}\(..\)\(..\).*$/0x\1, 0x\2}};/'`
    echo ""
    grep '<event symbol=' $SYSMONMSGOP | grep "win:Error" | sed -e 's/^.*symbol="\([^"]*\)".*value="\([^"]*\).*version="\([^"]*\)".*$/const EVENT_DESCRIPTOR \1 = {\2, \3, 0x10, 0x2, 0x0, \2, 0x8000000000000000};/'
    grep '<event symbol=' $SYSMONMSGOP | grep "win:Informational" | sed -e 's/^.*symbol="\([^"]*\)".*value="\([^"]*\).*version="\([^"]*\)".*$/const EVENT_DESCRIPTOR \1 = {\2, \3, 0x10, 0x4, 0x0, \2, 0x8000000000000000};/'
fi

