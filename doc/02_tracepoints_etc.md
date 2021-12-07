# Tracepoints etc

## Attachment points

There are two main types of attachment used in eBPF system observability. There 
are others for packet, routing and firewall use cases, but these are outside 
the scope of this document. The two types are tracepoints and kprobes. Most of 
this document is about tracepoints, but kprobes are mentioned for completeness.

## Tracepoints in general

Within the Linux kernel, numerous key points are annotated with tracepoint 
macros. These insert code that establish tracepoints at those points. The 
tracepoint architecture allows programs (tracers) to be easily attached to 
these points; essentially each consists of a linked-list of attached programs 
that will be called in order, each time the tracepoint is hit.

The reason why tracepoints are favoured over kprobes is because tracepoints 
rarely change from version to version. The names are consistent, their 
locations are consistent, and their parameters are consistent.

As each tracepoint specifies parameters relevant to the code where the 
tracepoint is located, programs attached to them receive them as their input 
parameters. Depending on the type of tracepoint, these parameters could relate 
to input parameters to a kernel function, could consist of useful status 
values, or could be an array containing register contents.

All tracepoints can be found in /sys/kernel/debug/tracing/events. This 
pseudo-directory contains directories representing the event classes; each of 
these contains directories representing the actual events; and these contain a 
number of pseudo-files that provide useful information or can be used to 
control the tracepoint (outside of eBPF).

The most important file (and the only one we use) is 'format'. This specifies 
the members of a struct that will be passed to a program attached to a 
tracepoint. Each line represents a single member and contains a type, a byte 
offset (into the struct), and a size in bytes. The members are divided into two 
parts, separated by a blank line. The members in the first part add up to 8 
bytes and are *completely inaccessible* to eBPF programs. The remainder make up 
the members that can be used.

For example:
```
name: sched_process_exec
ID: 289
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:__data_loc char[] filename;       offset:8;       size:4; signed:1;
        field:pid_t pid;        offset:12;      size:4; signed:1;
        field:pid_t old_pid;    offset:16;      size:4; signed:1;

print fmt: "filename=%s pid=%d old_pid=%d", __get_str(filename), REC->pid, REC->old_pid
```

To use a tracepoint, you can create a struct that starts with an opaque 
uint64\_t 'pad' member, followed by the members below the blank link - those 
starting at offset 8.

If the format includes any members of type \_\_data\_loc, then these are packed 
values, each containing the size of the field and the offset to the field. They 
can be decoded as:

* length = data\_loc >> 16
* offset = data\_loc & 0xFFFF

The offset is relative to the start of the parameters struct, and typically 
points to a location following the last member in the format. eBPF will only 
allow you to access memory contained in the struct. Therefore, in order to 
permit access to this memory, you'll need to include a member at the end of the 
struct that is large enough to include whatever data\_loc members exist. E.g. 
include a member at the end of the struct, 'char raw[4096]', in order to permit 
memory reads of up to 4KB from the end of the last member of the format.

The members of the struct - the ones included in the format - can be accessed 
like usual struct members, st-\>mem. The data\_loc members can be accessed via 
direct memory access, ((char \*)st) + offset. Use bpf\_probe\_read() and 
bpf\_probe\_read\_str() to efficiently copy them.

It is possible to see which tracepoints get hit, and the information they 
report, by running a command such as:

```
sudo perf trace --no-syscalls --event 'EVENT_CLASS:*'
```

where EVENT\_CLASS is a directory name under /sys/kernel/debug/tracing/events.

## Syscall tracepoints

Every syscall is annotated with a tracepoint on its entry and exit; these can 
be found in /sys/kernel/debug/tracing/events/syscalls, described in the same 
way as other tracepoints above. Syscalls are very stable (even compared with 
other tracepoints) and are a relatively good method of observing system 
activity initiated by userland applications, as syscalls are the only method 
that applications can use to access system resources.

Rather than specify the structs as described in the format file, it is also 
possible to define them as
```
struct tracepoint__syscalls__sys_enter {
    __uint64_t pad;
    __uint32_t __syscall_nr;
    __uint32_t pad2;
    __uint64_t a[6];
};

struct tracepoint__syscalls__sys_exit {
    __uint64_t pad;
    __uint32_t __syscall_nr;
    __uint32_t pad2;
    long ret;
};
```

Using this approach means the same structs can be used for all syscall enter 
and exit functions. It is imperative that the programs do not read arguments 
that do not exist. For example, if a syscall only takes one argument (e.g. 
uname), then only a[0] is valid, and a[1] to a[5] cannot be accessed (illegal 
operation).

The problem with syscall tracepoints is that they don't always tell the full 
story. Often syscalls have to be used in conjunction with other syscalls to 
cause things to happen; e.g. to initiate a TCP connection, an application needs 
to call socket(), optionally bind(), and connect(). Monitoring calls to 
connect() alone won't provide the details of the local socket address and port, 
only the remote ones specified in the struct sockaddr.

As the contents of the struct sockaddr are stored locally in the userland 
application's memory (only a pointer is sent to the syscall), the contents can 
be changed in parallel with the syscall being initiated, meaning the sockaddr 
that the kernel sees might be different to the sockaddr that an eBPF program 
will see if attached to the sys\_enter\_connect tracepoint.

These two issues could be solved by instead taking the socket file descriptor 
that was passed to connect() and looking up the details of the socket from 
that. Unfortunately, doing this in eBPF is tricky (without BTF at least), and 
looking it up in userland involves a race condition over file descriptors being 
reused - by the time the file descriptor has been provided to userland to be 
looked up, the file descriptor could potentially have been reused.

An alternative approach would be to monitor the sock/inet\_sock\_set\_state 
tracepoint as that provides details of the socket as it changes state. 
Unfortunately, the transition from SYN\_SENT to ESTABLISHED happens outside the 
context of the userland application (in a daemon or the kernel), so the 
task\_struct and PID are irrelevant, but this can be overcome by monitoring 
other state (see the chapter on networking for examples).

The relevance is that while syscall monitoring looks optimum, often it is not, 
and care still needs to be taken. Sometimes other non-syscall tracepoints will 
provide better insight.

When monitoring syscalls, the return code is often an important piece of 
information, as are the arguments supplied to it. As the arguments are only 
available at sys\_enter, and the return code at sys\_exit, both need to be 
monitored and the information collated.

## Raw\_syscalls tracepoints

In addition to the tracepoints at the entry and exit of each syscall, there are 
also tracepoints at the entry and exit of the entire syscall architecture, 
known as raw\_syscalls/sys\_enter and raw\_syscalls/sys\_exit. These take the 
same structs as defined above, and the attached programs are called on every 
syscall.

## Raw tracepoints

In addition to all the tracepoints as described above, from kernel v4.17 
onwards, it is possible to treat non-syscall tracepoints and raw\_syscalls 
tracepoints as 'raw tracepoints', using the program type 
BPF\_PROG\_TYPE\_RAW\_TRACEPOINT rather than BPF\_PROG\_TYPE\_TRACEPOINT, and 
the attach function bpf\_program\_\_attach\_raw\_tracepoint() rather than 
bpf\_program\_\_attach\_tracepoint().

To reiterate, individual syscall tracepoints cannot be attached to as raw 
tracepoints.

The main difference between the traditional method of attachment and the raw 
method, is that in the raw form the arguments haven't been 'cooked'. Taking the 
sched/sched\_process\_exec tracepoint as an example, we can look up the 
definition of the tracepoint in 
[/usr/src/include/trace/events/sched.h](https://elixir.bootlin.com/linux/v5.6.19/source/include/trace/events/sched.h#L312)
(all tracepoint classes have a header file in this directory) and can see the
following:

```
TRACE_EVENT(sched_process_exec,

	TP_PROTO(struct task_struct *p, pid_t old_pid,
		 struct linux_binprm *bprm),

	TP_ARGS(p, old_pid, bprm),

	TP_STRUCT__entry(
		__string(	filename,	bprm->filename	)
		__field(	pid_t,		pid		)
		__field(	pid_t,		old_pid		)
	),

	TP_fast_assign(
		__assign_str(filename, bprm->filename);
		__entry->pid		= p->pid;
		__entry->old_pid	= old_pid;
	),

	TP_printk("filename=%s pid=%d old_pid=%d", __get_str(filename),
		  __entry->pid, __entry->old_pid)
);
```

The TP\_PROTO() macro defines the raw tracepoint members of the parameters 
struct. Note: there is no 64 bit padding in the raw tracepoint struct. We can 
see there is a pointer to the task\_struct, the old PID, and a pointer to the 
linux\_binprm struct. The TP\_STRUCT\_\_entry() macro and the 
TP\_fast\_assign() macro state the same thing: they state how the parameters 
are cooked. In this example, we can see the cooked members are filename, pid, 
and old\_pid, which match up with the contents of the tracepoint's format file.

The noticeable difference in the parameters is that the filename is provided in 
the cooked condition, but you'd have to dereference it yourself in the raw 
version. For this example, I suspect that the cooked version (traditional 
tracepoint) makes more sense, assuming the filename is something you'd like. 
However, as this decision is based on the parameters available and those you 
require, other tracepoints might be just as useful in the raw form.

Due to the lack of cooking, raw tracepoints are faster than traditional 
tracepoints. The performance impact of cooking the parameters adds up so the 
decision is significant on busy systems.

A good example of where raw tracepoints make sense is with raw\_syscalls. Here 
the specification is as follows:

```
TRACE_EVENT_FN(sys_enter,

	TP_PROTO(struct pt_regs *regs, long id),

	TP_ARGS(regs, id),

	TP_STRUCT__entry(
		__field(	long,		id		)
		__array(	unsigned long,	args,	6	)
```

Aside from the syscall ID, the raw version contains a pointer to the registers, 
while the cooked version contains an array of arguments. As the arguments can 
be directly obtained from the registers (on 64 bit systems at least), the raw 
form gives us the same information, but without the minimal performance 
overhead.

## Kprobes

Kprobes - or kernel probes - are similar to tracepoints but can be inserted on 
any kernel function (and potentially any instruction). Whereas the tracepoint 
mechanism inserts the trampolines at compile time, kprobes create the 
trampolines on-the-fly, with a performance impact greater than that of 
tracepoints.

The other major difference with kprobes is that functions without tracepoints 
are far less stable in terms of function parameters and functionality; e.g. 
they could change from version to version. This leads to greater maintenance 
issues, and requires kernel symbols to be available to locate the functions.
