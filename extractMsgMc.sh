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
# extractMsgMc.sh
#
# Extracts defines from sysmonmsg.mc
#
#################################################################################


SYSMONMSG=sysmonmsg.mc

echo "// Copyright (c) 2021 Microsoft Corporation"

LINE1=`grep -n SeverityNames $SYSMONMSG | cut -d: -f1`
LINE2=`tail -n +$LINE1 $SYSMONMSG | grep -n ')' | head -n 1 | cut -d: -f1`
tail -n +$LINE1 $SYSMONMSG | head -n $LINE2 | grep : | sed -e 's/)//' | sed -e 's/^.*=0x\([^:]*\):\(.*\)$/#define \2 0x\1/'

LINE1=`grep -n FacilityNames $SYSMONMSG | cut -d: -f1`
LINE2=`tail -n +$LINE1 $SYSMONMSG | grep -n ')' | head -n 1 | cut -d: -f1`
tail -n +$LINE1 $SYSMONMSG | head -n $LINE2 | grep : | sed -e 's/)//' | sed -e 's/^.*=0x\([^:]*\):\(.*\)$/#define \2 0x\1/'

grep '^MessageId=0x.* Facility=Serial Severity=Error' $SYSMONMSG | sed -e 's/^MessageId=\(0x[^ ]*\).*SymbolicName=\(.*\)$/#define \2 ((NTSTATUS)(0xC0060000L + \1))/'
grep '^MessageId=0x.* Facility=Serial Severity=Warning' $SYSMONMSG | sed -e 's/^MessageId=\(0x[^ ]*\).*SymbolicName=\(.*\)$/#define \2 ((NTSTATUS)(0x80060000L + \1))/'
grep '^MessageId=0x.* Facility=Serial Severity=Informational' $SYSMONMSG | sed -e 's/^MessageId=\(0x[^ ]*\).*SymbolicName=\(.*\)$/#define \2 ((NTSTATUS)(0x40060000L + \1))/'
grep '^MessageId=0x.* Facility=Serial Severity=Success' $SYSMONMSG | sed -e 's/^MessageId=\(0x[^ ]*\).*SymbolicName=\(.*\)$/#define \2 ((NTSTATUS)(0x00060000L + \1))/'
