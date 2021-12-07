# Introduction to eBPF

## Introduction

eBPF is a fantastic technology that allows you to run code inside the Linux 
kernel. The difference between eBPF and kernel modules is:

* eBPF is safe, whereas kernel modules can crash the kernel;
* eBPF programs cannot access arbitrary memory;
* eBPF programs cannot call arbitrary kernel functions;
* eBPF programs have to pass verification in order to load;
* eBPF programs are limited in size and by the number of instructions they 
execute;
* eBPF programs are compiled to BPF bytecode and run in a virtual machine;
* compiled eBPF programs can be loaded into different kernels without 
recompilation (terms and conditions apply).

There are two main ways of building eBPF programs: BPF Compiler Collection 
(BCC) and libbpf. With BCC, the eBPF code is compiled *at runtime* (using 
LLVM/clang on the target machine), causing a start-up lag and placing heavy 
dependencies on the target machine. The libbpf approach involves compiling the 
eBPF code *at build time* and shipping it to the target machine as an ELF 
image. These documents only consider the libbpf approach as that is the one 
used by SysinternalsEBPF and Sysmon For Linux.

## Architecture

The basic architecture of an eBPF program comprises a userland component and an 
eBPF component. The userland component links with libbpf and it loads and 
communicates with the eBPF component. The eBPF component is made up of eBPF 
programs that are attached to code points within the kernel. The eBPF programs 
are verified on load, and each runs when their associated attachment point is 
reached in the kernel (think of these as hooks with trampolines). They run 
inside the eBPF virtual machine with limited (safe) access to memory and a 
minimal subset of kernel APIs.

eBPF programs typically consist of a single function and (apart from tail 
calls) cannot call other functions. However, eBPF code can be organised into 
*inline* functions that are inserted into the program at the point they are 
'called'. This approach improves readability and code organisation, permitting 
inline functions to be included in multiple eBPF programs without literally 
having to copy and paste.

Tail calls are a mechanism that allows one eBPF program to call another, but 
without passing parameters and without flow returning to the original program. 
Sysmon doesn't currently use tail calls but these might be a smart way to 
divide up functionality (to bypass instruction count and complexity limits) at 
the cost of additional CPU cycles.

eBPF programs can communicate with the userland component via maps (see next 
section) or via the perf ring buffer. This ring buffer has an API that makes it 
easy to send arbitrarily-sized 'samples' through it to the userland program. 
The userland side also has an API supplied by libbpf that causes a callback 
function to be called whenever a sample arrives.

The 'sample' can contain any data you choose (e.g. event data) but, while the 
size parameter is an unsigned 32 bit number, the maximum size of a sample is 
<64KB. The precise maximum size is system-dependent and ~(64KB - 48) but could 
be larger or smaller. It is not simple to discover this maximum size 
programmatically. If the maximum size is exceeded, then adjacent samples will 
overlap in memory and samples will become corrupted.

If the perf ring buffer becomes saturated, samples will be dropped. The 
userland API provides for a callback to signify the number of samples dropped.

When an eBPF program exits, control is returned to the point in the kernel 
where the eBPF program had been attached, and execution continues as if the 
eBPF program didn't exist.

## Memory Usage

eBPF programs are provided with 512 bytes of stack; as they can't call other 
functions (except tail calls where the entire stack is replaced), there are no 
stack frames (or rather the stack *is* the stack frame) and it only contains 
local variables. This memory is useful for counters, pointers, and potentially 
small temporary structs, but all other data structures need to be stored in 
'map memory'. There is no heap. Repeat: there is no heap.

eBPF provides a few basic data structures in the form of maps; the most popular 
two are arrays - 32 bit index and configurable size value - and hashes (similar 
to C++ unordered maps) - configurable size keys and values (with a built-in 
opaque hashing algorithm so you don't have to supply your own). Both types are 
shared between userland and eBPF, and both types require the maximum size to be 
specified at build time.

Maps, therefore, are the default method for the userland controller to 
communicate with the eBPF programs (configuration), for eBPF programs to store 
temporary state (larger local variables), for eBPF programs to communicate with 
themselves (maintaining state across multiple instantiations), and for eBPF 
programs to communicate with each other (sharing state and config).

Userland-specified configuration maps can be arranged in whatever way makes 
most sense, but typically they have a single entry (max\_entries = 1) where the 
value\_size is the sizeof(some\_config\_struct). The userland controller builds 
the struct and inserts it at index 0, and each eBPF program retrieves a pointer 
to the struct by retrieving the value at index 0. This configuration can be 
updated from both userland and eBPF and can be read from both sides, but 
typically the information flow is from userland to eBPF.

Local variables that are too big for the limited stack (e.g. event data that 
will be communicated with userland) are stored in eBPF maps. It is imperative 
to appreciate that the same eBPF program might be running on multiple cores 
simultaneously so care needs to be taken to ensure that they each use their own 
temporary memory.

If the value size is <=32KB then PER\_CPU arrays and hashes can be used but 
otherwise normal arrays should be used where the index is the CPU ID; this will 
ensure that each core's program sticks to memory allocated just for that core. 
The max\_entries should be set to the number of cores, or an arbitrarily large 
number if the maximum number of cores is not known at build time. (I typically 
set this to 512 as a trade-off between "big enough to accommodate most" and 
"not so big to waste all the memory".

Because eBPF programs can be attached at both the entry and exit of syscalls, 
it is typical to store temporary information from the entry program for the 
exit program to retrieve. The common way to do so is to create a hash with an 
arbitrary number of entries (probably much bigger than the number of cores in 
case syscalls sleep and many, many entry programs get hit before their 
corresponding exit programs get hit) where the key is the 64 bit value equal to 
the PID and TGID (obtained via a helper).

Note: in the kernel, PID refers to the Process ID (known as Thread ID or LWP in 
userland), and TGID refers to the Thread Group ID (known as PID in userland) - 
confusing to begin with, but important if you're to not mix them up.

Using the PID and TGID as the key ensures that entries will not overlap or 
overwrite each other, as it is impossible for a single thread to enter a new 
syscall before it has exited its current syscall. Therefore, data stored 
through this key will be certainly available at the exit point under the same 
key. It is imperative that this entry is removed by the exit program as hashes 
cannot grow in size or recycle old entries. Failing to remove used entries will 
simply fill up the hash and it will stop working.

Where eBPF programs use maps to share state with each other, any index or key 
approach can be used that makes sense. Where hashes are used, however, it is 
probably wise to periodically check and manage them from the userland as well. 
For example, it could be useful to maintain a second data structure with time 
entries to allow the userland to age-off old entries either as the hash fills 
up or simply because they are too old. There aren't any explicit locks, so the 
order of removing entries should be considered for situations where a race 
condition could occur.

## eBPF API

'man bpf\_helpers' will return a manual page detailing the API, known as 
'helpers' or 'helper functions'. Over time, helpers have been added as the eBPF 
support in kernels improved. There is no simple method of identifying which 
kernel version supports which helpers, but inspection of the eBPF subsystem in 
the kernel sources can provide indication.

The most simple approach is to identify the helpers available to the oldest 
kernel you wish to support and then stick to that list, regardless of whether 
new ones are available on the running kernel. That said, given the usefulness 
of some of the newer helpers (KRSI in v5.6 specifically), it might be wise to 
build programs that make use of the newer helpers if they are available. To do 
this, multiple versions of the programs would be required, and selected at run 
time.

The most commonly used helpers are:

* u32 bpf\_get\_smp\_processor\_id(void)
    - Returns the core number that the program is running on.
* u64 bpf\_get\_current\_pid\_tgid(void)
    - Returns the TGID and PID.
* u64 bpf\_get\_current\_uid\_gid(void)
    - Returns the UID and GID of the current process.
* u64 bpf\_get\_current\_task(void)
    - Returns a pointer to the task struct for the current process.
* u64 bpf\_ktime\_get\_ns(void)
    - Get time since boot, in nanoseconds.
* long bpf\_probe\_read(void \*dst, u32 size, const void \*unsafe\_ptr)
    - Read size bytes from unsafe\_ptr to dst.
* long bpf\_probe\_read\_str(void \*dst, u32 size, const void \*unsafe\_ptr)
    - Read string from unsafe\_ptr to dst, at most size bytes including the NUL 
character.
* void \*bpf\_map\_lookup\_elem(struct bpf\_map \*map, const void \*key)
    - Lookup key in array or hash
* long bpf\_map\_update\_elem(struct bpf\_map \*map, const void \*key, const 
void \*value, u64 flags)
    - Update element in array or hash. Flags are BPF\_NOEXIST (hash entry can't 
exist already), BPF\_EXIST (entry must exist already), and BPF\_ANY (don't 
care).
* long bpf\_map\_delete\_elem(struct bpf\_map \*map, const void \*key)
    - Delete element in array or hash.
* long bpf\_perf\_event\_output(void \*ctx, struct bpf\_map \*map, u64 flags, 
void \*data, u64 size)
    - Writes size bytes from data to the perf ring buffer specified in map. ctx is 
the first argument (a pointer) provided to the program.
* long bpf\_trace\_printk(const char \*fmt, u32 fmt\_size, ...)
    - printk (... can be up to 3 parameters) to /sys/kernel/debug/tracing/trace 
for debugging purposes only. (cat this pipe to see the messages.)

Most helpers return a negative error code or 0 for success. Some return values 
in-band. All should be checked for validity in case something went wrong.

## Performance Considerations

eBPF is fast! That's the good news. The bad news is that your eBPF programs run 
every time the kernel hits the attachment point in every thread of every 
process. Probably not a problem if your attachment is to sys\_enter\_uname as 
the uname() syscall probably doesn't get called that often. If, however, your 
attachment is to the raw sys\_enter tracepoint, then that's going to get hit 
every time a syscall is used in every program.

To reduce the performance hit, the aim should be to do as little work as 
possible in each eBPF program. Typically eBPF programs only care about 
particular circumstances; even where the program is planning on reporting every 
hit, errors in API calls will still result in the program exiting rather than 
reporting.

Performance improvements are therefore possible by collecting all the tests 
that could result in early exit, and positioning them at the start of the 
program. They should also be ordered by likelihood and performance impact, so 
that programs that exit before reporting, exit as early as possible, having 
done as little work as possible. We often can't help the amount of work needed 
to collect data and report, but every instruction executed on a non-repoting 
program adds to the system performance overhead.

Another place where performance hits can be managed is in the reporting of data 
over the perf ring buffer. Firstly, the API takes size-specified samples and 
handles them well - at the other end the API reveals the size as well - so 
avoid sending fixed-sized structs that are only partially completed or 
relevant. E.g. use a variable-length field for path names and command lines to 
avoid sending lots of empty memory following the actual data.

Secondly, only send data that you need to send; if there is no useful 
processing for data in userland, don't send it. Every byte saved in the 
transmitted samples reduces the chances of the ring buffer becoming saturated.

