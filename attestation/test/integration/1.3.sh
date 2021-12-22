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
( cd ${DST}/ras ; ./ras -T &>${DST}/ras/echo.txt ; ./ras &>>${DST}/ras/echo.txt ;)&
echo "wait for 5s"
sleep 5

# start number of rac clients
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t &>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done

### start monitoring and control the testing
echo "start to perform test ${TEST_ID}..." | tee -a ${DST}/control.txt
echo "wait for 1min"
sleep 60
# set the heartbeat cycle to 20s
echo "set the heartbeat cycle to 20s"
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"hbDuration","value":"20s"}]'
echo "wait for 1min"
sleep 60
# Query the heartbeat cycle of ras according to restapi, and read the log of ras
RESPONSE=$(curl http://localhost:40002/config)
echo ${RESPONSE} | tee -a ${DST}/control.txt

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent

echo "test DONE!!!" | tee -a ${DST}/control.txt

### analyse the testing data
rasHBDuration=$(echo $RESPONSE | jq -r '.' | grep -A 1 "hbDuration" | awk '/value/ {gsub("\"","",$2);print $2}')
if [ "$rasHBDuration" == "20s" ]
then
    echo "modify ras HBDuration succeeded!" | tee -a ${DST}/control.txt
else 
    echo "modify ras HBDuration failed!" | tee -a ${DST}/control.txt
fi

# compute true HBDuration
latestHBTime=$(cat ${DST}/ras/echo.txt | awk '/receive SendHeartbeat/ {gsub("^.*:","",$2);print $2}' | tail -n 3)
time1=$(echo ${latestHBTime} | awk '{print $1}')
time2=$(echo ${latestHBTime} | awk '{print $2}')
time3=$(echo ${latestHBTime} | awk '{print $3}')

### generate the test report
# Because time may be rounded up, one success is correct
if  [ $((${time2} - ${time1})) -eq 20 ] || [ $((${time3} - ${time2})) -eq 20 ]
then
    echo "modify HBDuration succeeded!"
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "modify HBDuration failed!"
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
