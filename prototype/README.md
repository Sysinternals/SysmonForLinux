# Sysmon For Linux Prototype
This is a prototype for Sysmon For Linux, developed to derisk the choice of XML
library.

This work currently only supports x64.

# Dependencies

- sudo apt update
- sudo apt install gcc g++ make cmake libelf-dev llvm clang

Please note, this project no longer requires kernel sources to build.

Please also note, that the version of clang needs to align with the kernel version
to some degree.  This is due to later versions of clang optimising out variable
clamps (var &= CONST_POWER_OF_2 -1, for example) where it can work out that the clamping
is unnecessary.  Unfortunately, the verifiers in earlier versions of the kernel don't
necessarily realise the limited range that a variable could hold, and therefore will
complain that indices could be negative, when clearly they could not.

As such:
* if you are running Ubuntu 16.04, please install clang+llvm 6;
* if you are running Ubuntu 18.04, please use the latest clang available to you, which
  should be 6;
* if you are running Ubuntu 20.04, please use the latest clang available to you, which
  should be 10;

For distros other than Ubuntu:
* if you are running kernel <=5.3, please install clang+llvm 6;
* if you are running kernel >=5.4, please install clang+llvm 10 or 11.

For multi-target use, please use clang+llvm 6.

Please make sure your cmake is >=v3.10.

# Clone
- git clone https://github.com/Sysinternals/SysmonForLinux.git
- cd SysmonForLinux/prototype

# Build
From the prototype directory:

- mkdir build
- cd build
- cmake ..
- make

# Configure
From the prototype/build directory:
- cd ../get_offsets
- make
- make conf > ../sysmon_offsets.conf
- cd ../build

Edit the sysmon-prototype.xml file to specify process creations to include/exclude.

# Run
From the prototype/build directory:

- sudo ./sysmon -i sysmon-prototype.xml

All events are sent to syslog.

# EBPF programs
There are 4 EBPF programs, each targetted at different EBPF capability levels:

- sysmon_kern_tp.c - for kernels without raw tracepoints, lower than v4.17
- sysmon_kern_raw_tp_sub4096.c - for kernels limited to 4096 instructions, v4.17 to v5.1
- sysmon_kern_raw_tp_noloops.c - for kernels that don't permit loops, v5.2
- sysmon_kern_raw_tp.c - for kernels that permit loops, v5.3 onwards

You can dump the EBPF assembler to reveal the number of instructions in a program with:

llvm-objdump -S -no-show-raw-insn EBPF_OBJECT_FILE.o

# Licenses
The main executable, sysmon, is licensed under MIT.
The ebpf_loader shared library is licensed under LGPL2.1.
The ebpf kernel objects are licensed under GPL2.

# Support
No support is provided.

# Feedback
Feel free to contact kevin.sheldrake [AT] microsoft.com to provide feedback or
ask questions.


