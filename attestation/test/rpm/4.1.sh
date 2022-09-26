#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
# run number of rac clients to test
NUM=5
. ${PROJROOT}/attestation/test/rpm/common.sh

### start ras
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ras -T &>${DST}/ras/echo.txt ; ras -v &>>${DST}/ras/echo.txt ;)&
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5

### start rahub
echo "start rahub..." | tee -a ${DST}/control.txt
( cd ${DST}/hub ; ./rahub -v &>>${DST}/hub/echo.txt ;)&
echo "wait for 3s"
sleep 3

### start rac
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    RACDIR=${DST}/rac-${i}
    mkdir -p ${RACDIR}
    cp ${HOMERACCONF}/config.yaml ${RACDIR}
    ( cd ${DST}/rac-${i} ; sudo raagent -v -s 127.0.0.1:40004 &>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done

AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
RESPONSE=$(curl -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" https://localhost:40003/)
echo ${RESPONSE} | tee -a ${DST}/control.txt
CLIENTNUM=$(echo $RESPONSE | jq -r '.' | awk '/id/ {gsub(",","",$2);print $2}' | wc -l | awk '{print $1}')
echo ${CLIENTNUM}
REPORT=$(curl -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" https://localhost:40003/1/reports)
### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent
pkill -u ${USER} rahub
echo "test DONE!!!" | tee -a ${DST}/control.txt

racmessage=$(cat ${DST}/rac-$((i-1))/echo.txt  | awk '/send trust report ok/ {print $1}')

### stop testing
if [ "${CLIENTNUM}" -eq 5 ] && [ "${racmessage}" != "" ] && [ "${REPORT}" != "[]" ]
then
    echo "all clients are registered!" | tee -a ${DST}/control.txt
    echo "rahub is functioning normally!" | tee -a ${DST}/control.txt
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi