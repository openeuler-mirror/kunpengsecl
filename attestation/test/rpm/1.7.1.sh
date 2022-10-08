#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
. ${PROJROOT}/attestation/test/rpm/common.sh

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt

### start ras
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ras -T &>${DST}/ras/echo.txt ; ras -v -H false &>>${DST}/ras/echo.txt ;)&
echo "wait for 3s" | tee -a ${DST}/control.txt
sleep 3

### start rac
echo "start rac at $(date)..." | tee -a ${DST}/control.txt
( cd ${DST}/rac ; sudo raagent -v &>${DST}/rac/echo.txt ; )&

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt
echo "wait for 20s"  | tee -a ${DST}/control.txt
sleep 20  | tee -a ${DST}/control.txt
# get cid
echo "get client id" | tee -a ${DST}/control.txt
cid=$(awk '{ if ($1 == "clientid:") { print $2 } }' ${HOMERACCONF}/config.yaml)
echo ${cid} | tee -a ${DST}/control.txt
echo "check server trust status via restapi request"  | tee -a ${DST}/control.txt
# get restapi auth token from echo.txt
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
RESPONSE=$(curl -H "Content-Type: application/json" http://localhost:40002/${cid})
echo ${RESPONSE} | tee -a ${DST}/control.txt

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent

echo "test DONE!!!" | tee -a ${DST}/control.txt

### analyse the testing data
STATUS=$(echo $RESPONSE | jq -r '.' | grep -A 0 "trusted" |  awk -F '"' '{print $4}')

### generate the test report
echo "ClientID:${cid}, Status:${STATUS}"  | tee -a ${DST}/control.txt
if [ "${STATUS}" == "trusted" ]
then
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
