# eBPF process\_exit example

This small eBPF program demonstrates how to build a simple tracepoint
program outside of the kernel tree, that doesn't rely on kernel sources.

Specifically, it demonstrates how to attach to the same tracepoint as
normal and as a raw tracepoint (which should be faster).

It builds and runs on kernel v4.15 and above.

* mkdir build
* cd build
* cmake ..
* make
* sudo ./user

Needs cmake>=3.10, clang, llvm and libelf-dev.  It fetches its own copy of
libbpf from github as part of configure and build.


