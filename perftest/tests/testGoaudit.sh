#!/bin/bash

sudo /opt/sysmon/sysmon -u > /dev/null
sudo service auditd stop
sudo service auoms stop
killall execPerSec
sudo auditctl -D > /dev/null

sudo go-audit/go-audit -config ./go-audit.yaml &
sleep 1

goauditpids=`ps -ef | grep go-audit | grep -v sudo | grep -v grep | awk '{print $2}'`
goauditpidargs=`for i in $goauditpids; do echo "-p $i "; done`
journaldpid=`ps -ef | grep systemd-journald | grep -v grep | awk '{print $2}'`
kauditdpid=`ps -ef | grep kauditd | grep -v grep | awk '{print $2}'`

for i in 100 200 400 800 1600; do
	execPerSec/execPerSec $i 50 &
	sleep 10
	RES=`pidstat -h -u $goauditpidargs -p $journaldpid -p $kauditdpid 30 1 | tail -n3 | awk '{print $8}'`
	CPU=`echo $RES | awk '{c=0;for(i=1;i<=NF;++i){c+=$i};print c}'`
	echo "go-audit,$i,$CPU"
	killall execPerSec
done

sudo killall go-audit
sudo auditctl -D > /dev/null

