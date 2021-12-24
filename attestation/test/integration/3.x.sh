#!/bin/bash
#this script run in centos
#use centos to test
cd /sys/kernel/security/ima
RESULT=`sudo cat ascii_runtime_measurements | grep $RESULT "\/sys\/fs\/cgroup\/devices\/system.slice\/network.service"`
if [ -z "$RESULT" ]
then
echo "test failed!"
else
echo "test successed!"
fi