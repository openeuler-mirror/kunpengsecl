#!/bin/bash
#this script run in centos
#use centos to test
service docker start
docker create ubuntu
cd /sys/kernel/security/ima
RESULT=`sudo cat ascii_runtime_measurements | grep $RESULT "\/docker\/image"`
if [ -z "$RESULT" ]
then
echo "test failed!"
else
echo "test successed!"
fi