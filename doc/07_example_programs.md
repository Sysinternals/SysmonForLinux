# Example Programs

## Introduction

This chapter describes the three example programs in the examples folder.

## Generic program structure

The kern.c file contains the eBPF code that will be loaded into the kernel, and 
the user.c file is its loader and controller. event\_defs.h is shared between 
both of them, and specifies the structs that are passed between the eBPF part 
and the userland part.

### eBPF part

The typical layout of the eBPF part consists of the following:

* includes
* defines
* maps - for perf ring buffer and any data structures
* structs for tracepoint arguments
* tracepoint programs

### Userland part

The typical layout of the userland part consists of the following:

* includes
* globals - bpf FDs, objects, programs and links
* bpf\_close\_all() - destroys the links
* print\_bpf\_output() - receives eBPF events from perf ring buffer
* handle\_lost\_events() - handles lost events
* intHandler() - handles ^C
* main() - sets up the eBPF:
    - setrlimit() - remove memory limitations
    - bpf\_object\_\_open() - access the eBPF ELF object
    - bpf\_object\_\_find\_program\_by\_title() - located program by ELF section
    - bpf\_object\_\_set\_type() - set the type of program; typically 
BPF\_PROG\_TYPE\_TRACEPOINT or BPF\_PROG\_TYPE\_RAW\_TRACEPOINT
    - bpf\_object\_\_load() - load eBPF programs into memory
    - bpf\_object\_\_find\_map\_fd\_by\_name() - locate map file descriptors
    - bpf\_program\_\_attach\_tracepoint() / 
bpf\_program\_\_attach\_raw\_tracepoint() - attach the programs to tracepoints
    - perf\_buffer\_\_new() - create a new perf buffer with event (sample) 
handling callbacks

## openat example

This example demonstrates how to attach to traditional syscall tracepoints, the 
overall syscall architecture tracepoints, and the overall syscall architecture 
as raw tracepoints. All three do the same thing and can be selected at run time 
by specifying 1, 2, or 3 on the command line.

The first type attaches to syscalls/sys\_enter\_openat and 
syscalls/sys\_exit\_openat. These are tracepoints specifically for the openat 
syscall and can only be attached to as traditional tracepoints (not raw). The 
enter program receives arguments specific to the openat syscall.

The second type attaches to raw\_syscalls/sys\_enter and 
raw\_syscalls/sys\_exit. These tracepoints are on the entry and exit of the 
entire syscall architecture so every syscall will hit them. The arguments to 
sys\_enter are generically a syscall ID and an array of six uint64\_t.

The third type attaches to the same as the second, but as raw tracepoints, 
which should be faster. The arguments are the CPU registers and the syscall ID.

Each of the enter programs stores the arguments; and each of the exit programs 
reads the filename and creates an event. As much of the work is the same, the 
exit programs call a shared inline function to do the work.

## execve example

This example demonstrates the various ways of attaching to tracepoints related 
to process creation. Different tracepoints provide different information, but 
typically (without access to kernel internals such as task\_struct) the 'exec' 
tracepoints get the program being executed and the PID, and the 'fork' 
tracepoints get the same plus the parent PID. These could be associated in 
userland if required.

Rather than specify which type to attach to on the command line, this program 
attaches to all at once and distinguishes them in the event struct and program 
output. Many of them share the write\_event() inline function to build and 
dispatch the event.

It is worth noting that task/task\_newtask receives the clone\_flags as part of 
its arguments, which can distinguish between fork() (new process) and clone() 
(new thread).

## process\_exit example

This example demonstrates how to attach to the same tracepoint as either 
traditional or raw. The execve tracepoints were not very useful as raw 
tracepoints because the raw arguments didn't provide much information; a 
program would have to navigate the task\_struct to find the details. The 
sched/process\_exit tracepoint, however, only receives useful information as 
arguments that can also be obtained through helpers, namely the PID and the 
comm.

