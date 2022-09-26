#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
. ${PROJROOT}/attestation/test/rpm/common.sh

### start ras
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ras -T &>${DST}/ras/echo.txt ; ras -v -H false &>>${DST}/ras/echo.txt ;)&
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt
# set the heartbeat cycle to 3s
echo "set the heartbeat cycle to 3s" | tee -a ${DST}/control.txt
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
curl -X POST -H "Authorization: $AUTHTOKEN" -d "hbduration=3s" http://localhost:40002/config
# Query the heartbeat cycle of ras according to restapi, and read the log of ras
RESPONSE=$(curl -H "Content-Type: application/json" http://localhost:40002/config)
echo ${RESPONSE} | tee -a ${DST}/control.txt

### start rac
echo "start rac at $(date)..." | tee -a ${DST}/control.txt
( cd ${DST}/rac ; sudo raagent -v &>${DST}/rac/echo.txt ; )&

echo "wait for 20s" | tee -a ${DST}/control.txt
sleep 20

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent

echo "test DONE!!!" | tee -a ${DST}/control.txt

### analyse the testing data
rasHBDuration=$(echo $RESPONSE | jq -r '.' | grep -A 0 "hbduration" | awk -F '"' '{print $4}')
if [ $rasHBDuration == "3s" ]
then
    echo "modify ras HBDuration succeeded!" | tee -a ${DST}/control.txt
else 
    echo "modify ras HBDuration failed!" | tee -a ${DST}/control.txt
fi

# compute true HBDuration
latestHBTime=$(cat ${DST}/rac/echo.txt | awk -F '"' '/send heart beat ok/ {print $8}' | tail -n 3)
echo "Latest 3 HB time: ${latestHBTime}" | tee -a ${DST}/control.txt
time1=$(echo ${latestHBTime} | awk '{print $1}' | awk -F ':' '{print $3}' | cut -c 1,2)
time2=$(echo ${latestHBTime} | awk '{print $2}' | awk -F ':' '{print $3}' | cut -c 1,2)
time3=$(echo ${latestHBTime} | awk '{print $3}' | awk -F ':' '{print $3}' | cut -c 1,2)

### generate the test report
# Because time may be rounded up, one success is correct
if  [ $((10#${time2} - 10#${time1})) -eq 3 ] || [ $((10#${time3} - 10#${time2})) -eq 3 ]
then
    echo "modify HBDuration succeeded!" | tee -a ${DST}/control.txt
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "modify HBDuration failed!" | tee -a ${DST}/control.txt
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi