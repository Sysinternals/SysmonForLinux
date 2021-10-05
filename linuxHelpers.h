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
// linuxHelpers.h
//
// Functions exported by linuxHelpers.cpp
//
//====================================================================

#include <sys/stat.h>
#include "linuxTypes.h"
#include "ioctlcmd.h"

typedef pthread_mutex_t CRITICAL_SECTION;

#ifdef __cplusplus
extern "C" {
#endif

void InitializeCriticalSection( CRITICAL_SECTION *p );
void EnterCriticalSection( CRITICAL_SECTION* p );
bool TryEnterCriticalSection( CRITICAL_SECTION* p );
void LeaveCriticalSection( CRITICAL_SECTION* p );
void DeleteCriticalSection( CRITICAL_SECTION *p );
BOOLEAN GetProcess( PSYSMON_EVENT_HEADER Process, size_t Len, ULONG ProcessId );
void SetBootTime();
BOOLEAN GetProcessInfo( LONGLONG* StartTime, ULONG* Pts, ULONG* Ppid, ULONG* Sessionid, ULONGLONG* ProcessKey, ULONG Pid );
BOOLEAN GetProcessName( char* ProcName, unsigned int Len, pid_t Pid );
BOOLEAN StrIsNum( const char* s );
BOOLEAN EnumProcesses( DWORD *lpidProcess, DWORD cb, PDWORD lpcbNeeded );
int StringFromGUID2( const GUID guid, PCHAR lpsz, int cchMax );
LARGE_INTEGER GetLogonTime( CONST LUID* user_luid );
VOID EventDataDescCreate( _In_ PEVENT_DATA_DESCRIPTOR EventDataDescriptor,
    _In_ const PVOID DataPtr, _In_ ULONG DataSize );
VOID GetSystemTimeAsLargeInteger( PLARGE_INTEGER timestamp );
time_t LargeTimeToSeconds( CONST PLARGE_INTEGER timestamp );
unsigned int LargeTimeMilliseconds( CONST PLARGE_INTEGER timestamp );
unsigned int LargeTimeNanoseconds( CONST PLARGE_INTEGER timestamp );
VOID LinuxFileTimeToLargeInteger( PLARGE_INTEGER timestamp, const my_statx_timestamp *filetime );
VOID LargeIntegerToSystemTimeString( char *s, size_t sLen, CONST PLARGE_INTEGER timestamp );
pid_t GetTid();

#ifdef __cplusplus
}
#endif
