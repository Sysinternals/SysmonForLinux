# Build

## Prerequisites
- SysinternalsEBPF being installed:
library `libsysinternalsEBPF.so`, header `libsysinternalsEBPF.h`, plus
resource files in `/opt/sysinternalsEBPF`. These can be installed from
the
[SysinternalsEBPF](https://github.com/Sysinternals/SysinternalsEBPF)
project or via the `sysinternalsebpf` DEB package from the
_packages.microsoft.com_ repository (see [INSTALL.md](INSTALL.md)).
If you installed SysinternalsEBPF via make install, you may need to add /usr/local/lib to the loader library path (LD_LIBRARY_PATH).

- .NET 6 SDK. Please see [.NET Installation](https://learn.microsoft.com/en-us/dotnet/core/install/linux)

- clang/llvm v10+

### Ubuntu 20.04+
```
sudo apt update
dotnet tool install --global dotnet-t4 --version 2.3.1
sudo apt -y install build-essential gcc g++ make cmake libelf-dev llvm clang libxml2 libxml2-dev libzstd1 git libgtest-dev apt-transport-https dirmngr googletest google-mock libgmock-dev libjson-glib-dev
```

### Ubuntu 18.04
```
sudo apt update
dotnet tool install --global dotnet-t4 --version 2.3.1
sudo apt -y install build-essential gcc g++ make cmake libelf-dev llvm clang libxml2 libxml2-dev libzstd1 git libgtest-dev apt-transport-https dirmngr googletest google-mock libjson-glib-dev
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

### Rocky 9
```
sudo dnf install dnf-plugins-core
sudo dnf config-manager --set-enabled crb
sudo dnf install epel-release

sudo dnf update
dotnet tool install --global dotnet-t4 --version 2.3.1
sudo yum install gcc gcc-c++ make cmake llvm clang elfutils-libelf-devel rpm-build json-glib-devel python3 libxml2-devel gtest-devel gmock gmock-devel
```

### Rocky 8
```
sudo dnf install dnf-plugins-core
sudo dnf install epel-release
sudo dnf config-manager --set-enabled powertools

sudo dnf update
dotnet tool install --global dotnet-t4 --version 2.3.1
sudo yum install gcc gcc-c++ make cmake llvm clang elfutils-libelf-devel rpm-build json-glib-devel python3 libxml2-devel gtest-devel gmock gmock-devel
```

### Debian 11
```
wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt update
dotnet tool install --global dotnet-t4 --version 2.3.1
sudo apt -y install build-essential gcc g++ make cmake libelf-dev llvm clang libzstd1 git libjson-glib-dev libxml2 libxml2-dev googletest google-mock libgmock-dev
```

### Debian 10
```
wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb
sudo apt update
dotnet tool install --global dotnet-t4 --version 2.3.1
sudo apt -y install build-essential gcc g++ make cmake libelf-dev llvm clang libzstd1 git libjson-glib-dev libxml2 libxml2-dev googletest google-mock libgmock-dev
```

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