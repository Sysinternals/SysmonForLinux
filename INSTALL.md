# Install Sysmon

## Ubuntu 18.04, 20.04 & 21.04
#### 1. Register Microsoft key and feed
```sh
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
```

#### 2. Install SysmonForLinux
```sh
sudo apt-get update
sudo apt-get install sysmonforlinux
```

## Debian 10
#### 1. Register Microsoft key and feed
```sh
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg
sudo mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/
wget -q https://packages.microsoft.com/config/debian/10/prod.list
sudo mv prod.list /etc/apt/sources.list.d/microsoft-prod.list
sudo chown root:root /etc/apt/trusted.gpg.d/microsoft.asc.gpg
sudo chown root:root /etc/apt/sources.list.d/microsoft-prod.list
```

#### 2. Install SysmonForLinux
```sh
sudo apt-get update
sudo apt-get install apt-transport-https
sudo apt-get update
sudo apt-get install sysmonforlinux
```

## Debian 11
#### 1. Register Microsoft key and feed
```sh
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg
sudo mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/
wget -q https://packages.microsoft.com/config/debian/11/prod.list
sudo mv prod.list /etc/apt/sources.list.d/microsoft-prod.list
sudo chown root:root /etc/apt/trusted.gpg.d/microsoft.asc.gpg
sudo chown root:root /etc/apt/sources.list.d/microsoft-prod.list
```

#### 2. Install SysmonForLinux
```sh
sudo apt-get update
sudo apt-get install apt-transport-https
sudo apt-get update
sudo apt-get install sysmonforlinux
```

## Fedora 33
#### 1. Register Microsoft key and feed
```sh
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
sudo wget -q -O /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/fedora/33/prod.repo
```

#### 2. Install SysmonForLinux
```sh
sudo dnf install sysmonforlinux
```

## Fedora 34
#### 1. Register Microsoft key and feed
```sh
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
sudo wget -q -O /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/fedora/34/prod.repo
```

#### 2. Install SysmonForLinux
```sh
sudo dnf install sysmonforlinux
```

## RHEL 8
#### 1. Register Microsoft key and feed
```sh
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
sudo wget -q -O /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/rhel/8/prod.repo
```

#### 2. Install SysmonForLinux
```sh
sudo dnf install sysmonforlinux
```

## CentOS 8
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/centos/8/packages-microsoft-prod.rpm
```

#### 2. Install SysmonForLinux
```sh
sudo dnf install sysmonforlinux
```

## openSUSE 15
#### 1. Register Microsoft key and feed
```sh
sudo zypper install libicu
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
wget -q https://packages.microsoft.com/config/opensuse/15/prod.repo
sudo mv prod.repo /etc/zypp/repos.d/microsoft-prod.repo
sudo chown root:root /etc/zypp/repos.d/microsoft-prod.repo
```

#### 2. Install SysmonForLinux
```sh
sudo zypper install sysmonforlinux
```

## SLES 15
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/sles/15/packages-microsoft-prod.rpm
```

#### 2. Install SysmonForLinux
```sh
sudo zypper install sysmonforlinux
```

