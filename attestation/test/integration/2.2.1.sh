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
echo "sleep 5s" | tee -a ${DST}/control.txt
sleep 5

# start number of rac 
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t &>>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5

# register container
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/container/9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9 --data '{"registered":true,"serverid":1,"uuid":"9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9"}'

# get the container information
GETCONTAINER1=$(curl http://localhost:40002/container/9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9)
echo ${GETCONTAINER1} | tee -a ${DST}/control.txt

# delete the container
curl -X PUT -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/container/9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9 --data 'false'

# get the container information
GETCONTAINER2=$(curl http://localhost:40002/container/9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9)
echo ${GETCONTAINER2} | tee -a ${DST}/control.txt

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent

echo "test DONE!!!" | tee -a ${DST}/control.txt

### analyse the testing data
CLIENTID1=$(echo ${GETCONTAINER1} | jq -r '.' | awk '/UUID/ {gsub(",","",$2);print $2}')
STATUS1=$(echo ${GETCONTAINER1} | jq -r '.' | awk '/Deleted/ {gsub(",","",$2);gsub("\"","",$2);print $2}')
CLIENTID2=$(echo ${GETCONTAINER2} | jq -r '.' | awk '/UUID/ {gsub(",","",$2);print $2}')
STATUS2=$(echo ${GETCONTAINER2} | jq -r '.' | awk '/Deleted/ {gsub(",","",$2);gsub("\"","",$2);print $2}')

### generate the test report
echo "First time: UUID:${CLIENTID1}, Status:${STATUS1}" | tee -a ${DST}/control.txt
echo "Second time: UUID:${CLIENTID2}, Status:${STATUS2}" | tee -a ${DST}/control.txt
if [[ "${STATUS1}" == "false"  && "${STATUS2}" == "true" ]]
then
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
