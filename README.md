# Sysmon For Linux install and build instructions [![Build Status](https://dev.azure.com/sysinternals/Tools/_apis/build/status/Sysinternals.SysmonForLinux?repoName=Sysinternals%2FSysmonForLinux&branchName=main)](https://dev.azure.com/sysinternals/Tools/_build/latest?definitionId=340&repoName=Sysinternals%2FSysmonForLinux&branchName=main)

## Installation
The packages are available in the official Microsoft Linux repositories and instructions on how to install the packages for the different Linux distributions can be found in the [Installation instructions](INSTALL.md).

This project contains the code for build and installing [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) on Linux.

## Dependencies
For Ubuntu 20.04 and later:
```
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
echo "deb https://download.mono-project.com/repo/ubuntu vs-bionic main" | sudo tee /etc/apt/sources.list.d/mono-official-vs.list
sudo apt update
sudo apt -y install build-essential gcc g++ make cmake libelf-dev llvm clang libxml2 libxml2-dev libzstd1 git libgtest-dev apt-transport-https dirmngr monodevelop googletest google-mock libgmock-dev libjson-glib-dev
```
for Ubuntu 18.04:

```
sudo apt -y install build-essential gcc g++ make cmake libelf-dev llvm clang libxml2 libxml2-dev libzstd1 git libgtest-dev apt-transport-https dirmngr monodevelop googletest google-mock libjson-glib-dev
mkdir googletest-build
cd googletest-build
cmake /usr/src/googletest
make
sudo make install
```
The googletest-related libraries are built from source and installed
under `/usr/local`:
- `/usr/local/include/gtest`
- `/usr/local/include/gmock`
- `/usr/local/lib/libgtest*.a`
- `/usr/local/lib/libgmock*.a`

Sysmon For Linux also depends on SysinternalsEBPF being installed:
library `libsysinternalsEBPF.so`, header `libsysinternalsEBPF.h`, plus
resource files in `/opt/sysinternalsEBPF`. These can be installed from
the
[SysinternalsEBPF](https://github.com/Sysinternals/SysinternalsEBPF)
project or via the `sysinternalsebpf` DEB package from the
_packages.microsoft.com_ repository (see [INSTALL.md](INSTALL.md)).

## Build
```
cd
git clone --recurse-submodules https://github.com/Sysinternals/SysmonForLinux.git
cd SysmonForLinux
mkdir build
cd build
cmake ..
make
```

## Test
```
./sysmonUnitTests
```

## Run
```
sudo ./sysmon -?
```

## Install
```
sudo ./sysmon -accepteula
sudo ./sysmon -i CONFIG_FILE
```
This will install sysmon and associated files into the /opt/sysmon directory.
The binary is portable and self-contained - the build process packs the
required files into the binary for installation with '-i'. Sysmon will restart
on reboot with the same configuration.

Change the configuration with
```
sudo /opt/sysmon/sysmon -c CONFIG_FILE
```

Uninstall sysmon with
```
sudo /opt/sysmon/sysmon -u
```

## Make Packages
Packages can be generated with:
```
make packages
```
The directories build/deb and build/rpm will be populated with the required
files. If dpkg-deb is available, the build/deb directory will be used to create
a deb package. Similarly if rpmbuild is available, the build/rpm directory will
be used to create an rpm package.

## Autodiscovery of Offsets
Sysmon attempts to automatically discover the offsets of some members of some
kernel structs. If this fails, please provide details of the kernel version
(and config if possible) plus the error message to the GitHub issues page.

You can then generate a configuration file to override the autodiscovery by
building the getOffsets module in the /opt/sysinternals/getOffsets directory.
See the README.md in that directory for more information.

## Manual Page
A man page for Sysmon can be found in the package directory, and is installed
by both deb and rpm packages.

Use 'find' on the package directory to locate it manually.

## Output
```
sudo tail -f /var/log/syslog
```
or more human-readable
```
sudo tail -f /var/log/syslog | sudo /opt/sysmon/sysmonLogView
```

SysmonLogView has options to filter the output to make it easy to identify
specific events or reduce outputted fields for brevity.

SysmonLogView is built when Sysmon is built and is installed into /opt/sysmon
when sysmon is installed.

*Important*: You may wish to modify your Syslogger config to ensure it can
handle particularly large events (e.g. >64KB, as defaults are often between 1KB
and 8KB), and/or use the FieldSizes configuration entry to limit the length of
output for some fields, such as CommandLine, Image, CurrentDirectory, etc.

Example:

Add \<FieldSizes\>CommandLine:100,Image:20\</FieldSizes\> under
\<Sysmon\> in your configuration file.

## Developer Details
See DEVELOP.md

## License
Sysmon For Linux is licensed under MIT, with the eBPF programs licensed under
GPL2.  SysinternalsEBPF (on which Sysmon For Linux depends) is licensed under
LGPL2.1, with the eBPF code library licensed under GPL2.

