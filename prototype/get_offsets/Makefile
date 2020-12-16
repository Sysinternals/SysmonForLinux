#    SysmonForLinux
#
#    Copyright (c) Microsoft Corporation
#
#    All rights reserved.
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

obj-m += get_offsets.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	$(info Use 'make run' to get the offsets)
	$(info Use 'make conf' to generate the configuration file; save to ../ebpf_telemetry.conf)

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
run:
	sudo dmesg -C
	sudo insmod get_offsets.ko
	sudo rmmod get_offsets.ko
	dmesg
conf:
	@sudo dmesg -C
	@sudo insmod get_offsets.ko
	@sudo rmmod get_offsets.ko
	@dmesg | grep '^\[' | tail -n +3 | head -n -2 | cut -d']' -f2- | cut -d' ' -f2-
