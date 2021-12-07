# eBPF openat example

This small eBPF program demonstrates how to build a simple tracepoint
program outside of the kernel tree, that doesn't rely on kernel sources.

Specifically, it shows how to connect to syscall tracepoints.

It builds and runs on kernel v4.15 and above.

* mkdir build
* cd build
* cmake ..
* make
* sudo ./user

Needs cmake>=3.10, clang, llvm and libelf-dev.  It fetches its own copy of
libbpf from github as part of configure and build.

The user program takes a single argument to specify which version of eBPF
code to run:

* 1 = tracepoints syscalls/sys\_openat\_enter / exit
* 2 = tracepoints raw\_syscalls/sys\_enter / exit
* 3 = raw tracepoints raw\_syscalls/sys\_enter / exit

Each version does the same thing - reports the filepath, flags and mode of
files successfully opened with the openat() syscall. The first connects
directly to the openat enter and exit (traditional tracepoints); the second
connects to the enter and exit for the syscall architecture (traditional
tracepoints again); and the third connects to the raw tracepoints at the
enter and exit of the syscall architecture. It is not possible to connect
to the openat syscall enter and exit as raw tracepoints.

