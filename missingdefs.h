/*
    SysmonForLinux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

//====================================================================
//
// missingdefs.h
//
// Defines types that are not available in vmlinux.h
//
// Unfortunately, today, when including vmlinux.h there is no way to 
// prevent redefinitions and hence we need to remove all headers that
// cause redefitions. By doing so however, we also miss the defitions
// in those headers that vmlinux.h does not define. This is a known 
// problem and the current solution is to define those types seperately. 
// This files contains all the defs that are missing. 
//
// For more detail, please see:
// https://lore.kernel.org/bpf/CAO658oV9AAcMMbVhjkoq5PtpvbVf41Cd_TBLCORTcf3trtwHfw@mail.gmail.com/ 
//
//====================================================================

#pragma once

// If we're not compiling eBPF programs, the below will not be defined. 
#ifndef EBPF_CO_RE
enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT = 2,
    TCP_SYN_RECV = 3,
    TCP_FIN_WAIT1 = 4,
    TCP_FIN_WAIT2 = 5,
    TCP_TIME_WAIT = 6,
    TCP_CLOSE = 7,
    TCP_CLOSE_WAIT = 8,
    TCP_LAST_ACK = 9,
    TCP_LISTEN = 10,
    TCP_CLOSING = 11,
    TCP_NEW_SYN_RECV = 12
};
#endif

#ifndef AT_FDCWD
#define AT_FDCWD		    -100
#endif

#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR		0x200 
#endif

#ifndef O_CREAT
#define O_CREAT            0100
#endif 

#ifndef PTRACE_ATTACH
#define PTRACE_ATTACH              16
#endif

#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE             0x4206
#endif