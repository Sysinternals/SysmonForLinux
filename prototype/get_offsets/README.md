# SysmonForLinux prototype get_offsets
This is a prototype for Sysmon For Linux, developed to derisk the choice of XML
library.

This work currently only supports x64.

get_offsets is a kernel module that obtains the offsets into kernel internals
and generates content for a ebpf_telemetry.conf file.  This file is required
for ebpf_telemetry to be able to access kernel structs.

# Dependencies
- sudo apt install make gcc

# Build
From the SysmonForLinux/prototype/get_offsets *on the target machine* directory:

- make

# Run
From the SysmonForLinux/prototype/get_offsets *on the target machine* directory:

- make run

# Generate config file
From the SysmonForLinux/prototype/get_offsets *on the target machine* directory:

- make conf > ../ebpf_telemetry.conf

# mount.h
get_offsets includes mount.h taken verbatim from the source of v4.15 of the Linux kernel.
This file can often be found at /usr/src/linux/fs/mount.h.
This source file hasn't materially changed (at least in relation to the struct mount that
we require) between v4.0 and v5.8 of the Linux kernel.  Post v5.8, if the definition of
struct mount changes, the source file get_offsets.c can be simply modified to pick up the
version in the Linux source - this will require the source code.  Alternatively, a suitable
version of this file can be extracted from the relevant archive of the kernel source and
placed in the SysmonForLinux/prototype/get_offsets directory.

# Licenses
get_offsets is licensed under GPL2.
get_offsets includes mount.h taken verbatim from the source of v4.15 of the Linux kernel;
this file is licensed under GPL2.

# Support
No support is provided.

# Feedback
Feel free to contact kevin.sheldrake [AT] microsoft.com to provide feedback or
ask questions.


