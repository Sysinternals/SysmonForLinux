# Reading Memory

## Introduction

As eBPF is a safe language, it will only allow you to read memory that you 
either own yourself, or has been accessed correctly via a helper. This chapter 
discusses how to access memory correctly and the issues with it.

## Memory you own

You own the following memory and therefore can read it without issue:

* Parameters passed to eBPF programs;
* Local eBPF stack variables;
* Retrieved entries from maps;

You can dereference and read this memory directly, with the usual C language 
instructions, including memcpy(), which is usually inlined by the compiler for 
you. If memcpy() is prohibited by the verifier, you can swap it with 
bpf\_probe\_read(). Take care as the parameters are in a different order.

## Memory accessed via a helper

All other memory access must go via a helper, such as bpf\_probe\_read() and 
bpf\_probe\_read\_str(). These helpers must be used to dereference and read 
memory from the task\_struct, any structs linked from it, and any userland 
memory.

## Issues

The only real issue with reading memory is that, usually, eBPF programs cannot 
'sleep', which means they cannot access memory that is paged out.

Memory is paged in when it is required, and is paged out when it hasn't been 
accessed for a while and another chunk of memory needs its slot. Outside of 
eBPF, when a program attempts to access paged-out memory, an interrupt occurs 
handing control temporarily to the interrupt handler in the kernel. This 
pages-in the required memory chunk, then resets the program counter back to the 
faulting instruction, and returns from the interrupt handler.

This process happens automatically in non-eBPF situations; memory appears to be 
seamlessly paged in as it is required and programs are largely unaware of it 
happening (although timing could probably be used to identify it).

eBPF programs usually cannot sleep. This means that interrupts are suspended 
when they run, preventing the above process from happening. Instead, when an 
eBPF program attempts to access paged-out memory via a helper, the call to the 
helper fails with an error code, and the destination buffer is zeroed.

## Avoiding paged-out memory

The way to avoid the situation is to only read memory after it has recently 
been accessed, causing the likelihood of it being paged-in to be high. For 
syscall tracepoints, this can be achieved by only reading memory in programs 
attached to the exit tracepoints. The logic is that the kernel will have 
accessed the memory that you are interested in, just prior to you attempting 
access.

With non-syscall tracepoints, there is no enter and exit, just the tracepoint. 
But often there are multiple tracepoints in the same event class or related 
events in other classes that occur in the same execution path. By exploring 
these it may be possible to find an event that occurs after the desired memory 
has been accessed by the kernel. It may be necessary to combine information 
from different tracepoints, accessing some information in one tracepoint and 
other information in another.
