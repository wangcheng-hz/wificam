#!/bin/sh

set -u
set -e

systemdir="/usr/lib/systemd/system/"
sysctldir="/etc/sysctl.d/"

cp ./redis.conf /etc/redis.conf
cp ./redis.service $systemdir/
cp ./wifiscan.conf $sysctldir/

systemctl daemon-reload
systemctl enable redis
systemctl restart redis
systemctl restart systemd-sysctl


