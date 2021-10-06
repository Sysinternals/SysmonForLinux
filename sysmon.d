#!/bin/sh

#    SysmonForLinux
#
#    Copyright (c) Microsoft Corporation
#
#    All rights reserved.
#
#    MIT License
#
#    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
#    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

set -e
. /lib/lsb/init-functions

start() {
    printf "Starting sysmon..."
    start-stop-daemon --start --chuid "root:root" --background --make-pidfile --pidfile /var/run/sysmon.pid --chdir "/opt/sysmon" --exec "/opt/sysmon/sysmon" -- -i /opt/sysmon/config.xml -service
    printf "done\n"
}

stop() {
    printf "Stopping sysmon..."
    kill `cat /var/run/sysmon.pid`
    sleep 1
    if [ -d /proc/`cat /var/run/sysmon.pid` ]; then
        kill -9 `cat /var/run/sysmon.pid`
    fi
    rm /var/run/sysmon.pid
    printf "done\n"
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    *)
        echo "Usage: sysmon {start|stop|restart}"
        exit 1
        ;;
esac

exit 0

