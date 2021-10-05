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
// sysmonProcCreate.c
//
// Report process creation events as a result of execve()execveat().
//
//====================================================================

__attribute__((always_inline))
static inline char* set_process_ext(
    PSYSMON_PROCESS_CREATE event,
    const ebpfConfig *config,
    const void *task
    )
{
    char *ptr = NULL;
    uint64_t extLen = 0;

    ptr = (char *)(event + 1);
    memset(event->m_Extensions, 0, sizeof(event->m_Extensions));

    // Insert the UID as the SID
    *(uint64_t *)ptr = event->m_AuthenticationId.LowPart;
    event->m_Extensions[PC_Sid] = sizeof(uint64_t);
    ptr += sizeof(uint64_t);

    extLen = derefFilepathInto(ptr, task, config->offsets.exe_path, config);
    event->m_Extensions[PC_ImagePath] = extLen;

    // Following piece of asm is required because without it clang puts extLen
    // onto the stack after the first statement (bounding it with (PATH_MAX - 1))
    // and when it retrieves it, the verifier has forgotten that it was bounded.
    // The asm performs the equivalent of the following C statements, but by doing
    // it in asm, it magically happens all in registers without hitting the stack.
    //
    //    extLen &= (PATH_MAX -1);
    //    ptr += extLen;

    asm volatile("%[extLen] &= " XSTR(PATH_MAX - 1) "\n"
                 "%[ptr] += %[extLen]"
                 :[extLen]"+&r"(extLen), [ptr]"+&r"(ptr)
                 );

    extLen = copyCommandline(ptr, task, config);
    event->m_Extensions[PC_CommandLine] = extLen;
    ptr += (extLen & (CMDLINE_MAX_LEN - 1));
    extLen = derefFilepathInto(ptr, task, config->offsets.pwd_path, config);
    event->m_Extensions[PC_CurrentDirectory] = extLen;
    ptr += (extLen & (PATH_MAX - 1));

    return ptr;
}

__attribute__((always_inline))
static inline char* set_ProcCreate_info(
    PSYSMON_EVENT_HEADER eventHdr,
    const ebpfConfig *config,
    uint64_t pidTid,
    uint32_t cpuId,
    const argsStruct *eventArgs
    )
{
    const void *task = NULL;
    const void *p_task = NULL;
    const void *cred = NULL;
    char *ptr = NULL;
    uint64_t extLen = 0;

    if (eventHdr == NULL || config == NULL || eventArgs == NULL)
        return (char *)eventHdr;

    // only record successful process creations
    if (eventArgs->returnCode != 0)
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

    eventHdr->m_EventType = ProcessCreate;
    PSYSMON_PROCESS_CREATE event = &eventHdr->m_EventBody.m_ProcessCreateEvent;

    // set the pid
    event->m_ProcessId = pidTid >> 32;

    // set the process objects (task ptrs)
    p_task = (const void *)derefPtr(task, config->offsets.parent);

    event->m_ProcessObject = (PVOID)task;
    event->m_ParentProcessObject = (PVOID)p_task;

    // get the ppid
    event->m_ParentProcessId = (uint32_t)derefPtr(p_task, config->offsets.pid);

    // get the session
    if (config->offsets.auid[0] != -1) {
        event->m_AuditUserId = (uint32_t)derefPtr(task, config->offsets.auid);
        event->m_SessionId = (uint32_t)derefPtr(task, config->offsets.ses);
    } else {
        event->m_AuditUserId = -1;
        event->m_SessionId = -1;
    }

    // get the creds
    cred = (const void *)derefPtr(task, config->offsets.cred);
    if (cred) {
        event->m_AuthenticationId.LowPart = (uint32_t)derefPtr(cred, config->offsets.cred_uid);
        event->m_AuthenticationId.HighPart = (uint32_t)derefPtr(task, config->offsets.tty);
    } else {
        BPF_PRINTK("ERROR, failed to deref creds\n");
        event->m_AuthenticationId.LowPart = -1;
        event->m_AuthenticationId.HighPart = -1;
    }

    // get the process key - this is the end of the text segment currently as it should be
    // a) randomised for a PIE executable; and
    // b) dependent on the amount of code in the process
    event->m_ProcessKey = (uint64_t)derefPtr(task, config->offsets.mm_end_code);

    // get process start time - this is in nanoseconds and we want 100ns intervals
    event->m_CreateTime.QuadPart = (derefPtr(task, config->offsets.start_time) + config->bootNsSinceEpoch) / 100;
    return set_process_ext(event, config, task);
}

