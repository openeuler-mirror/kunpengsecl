#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
# run number of rac clients to test
NUM=1
# include common part
. ${PROJROOT}/attestation/test/integration/common.sh

# above are common preparation steps, below are specific preparation step, scope includs:
# configure files, input files, environment variables, cmdline paramenters, flow control paramenters, etc.
### Start Preparation
echo "start test preparation..." | tee -a ${DST}/control.txt
pushd $(pwd)
cd ${PROJROOT}/attestation/quick-scripts
echo "clean database" | tee -a ${DST}/control.txt
sh clear-database.sh | tee -a ${DST}/control.txt
popd
### End Preparation

### start launching binaries for testing
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ./ras -T &>${DST}/ras/echo.txt ; ./ras -v &>>${DST}/ras/echo.txt ;)&
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt
# set the heartbeat cycle to 3s
echo "set the heartbeat cycle to 3s" | tee -a ${DST}/control.txt
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
curl -X POST -k -H "Authorization: $AUTHTOKEN" -d "hbduration=2m0s" https://localhost:40003/config
# Query the heartbeat cycle of ras according to restapi, and read the log of ras
RESPONSE=$(curl -k -H "Content-Type: application/json" https://localhost:40003/config)
echo ${RESPONSE} | tee -a ${DST}/control.txt

# start number of rac clients
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t true -v &>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done

echo "wait for 20s" | tee -a ${DST}/control.txt
sleep 20

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent

echo "test DONE!!!" | tee -a ${DST}/control.txt

### analyse the testing data
rasHBDuration=$(echo $RESPONSE | jq -r '.' | grep -A 0 "hbduration" |  awk -F '"' '{print $4}')
if [ $rasHBDuration == "3s" ]
then
    echo "modify ras HBDuration succeeded!" | tee -a ${DST}/control.txt
else 
    echo "modify ras HBDuration failed!" | tee -a ${DST}/control.txt
fi

# compute true HBDuration
latestHBTime=$(cat ${DST}/rac-$((i-1))/echo.txt | awk -F '"' '/send heart beat ok/ {print $8}' | tail -n 3)
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