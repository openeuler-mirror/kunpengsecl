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
echo "start test ${CASENAME} preparation..." | tee -a ${DST}/control.txt
pushd $(pwd)
cd ${PROJROOT}/attestation/quick-scripts
echo "clean database" | tee -a ${DST}/control.txt
sh clear-database.sh | tee -a ${DST}/control.txt
popd
### End Preparation

### start launching binaries for testing
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ./ras -T &>${DST}/ras/echo.txt ; ./ras &>>${DST}/ras/echo.txt ;)&
echo "sleep 10s" | tee -a ${DST}/control.txt
sleep 10

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
echo "start to perform test ${TEST_ID}..." | tee -a ${DST}/control.txt
echo "wait for 5s"
sleep 5
# stop rac
echo "kill all raagent processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} raagent

# modify ima file
NEWLINE1="10 db4049d7fe6443ceeedd2d2eda1f35c41d7b100a ima e24ab5cc872cecc94dbc8baf9d33246bf22af042 /usr/lib64/NetworkManager/1.18.8-1.el7/libnm-device-plugin-wifi.so"
echo "${NEWLINE1}" >> ${RACDIR}/${IMAFILE}

# restart number of rac 
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

# register device
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/device/1234567 --data '{"id":1234567,"registered":true,"serverid":1}'

# post basevalue
echo "post basevalue ing..." | tee -a ${DST}/control.txt
curl -X PUT -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/device/basevalue/1234567 --data '{"measurements":[{"name":"/usr/lib64/NetworkManager/1.18.8-1.el7/libnm-device-plugin-wifi.so","type":"ima","value":"db4049d7fe6443ceeedd2d2eda1f35c41d7b100a"}]}'

echo "wait for 90s"
sleep 90

# get-response
RESPONSE=$(curl http://localhost:40002/device/status)
echo ${RESPONSE} | tee -a ${DST}/control.txt

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent

echo "test DONE!!!" | tee -a ${DST}/control.txt

### analyse the testing data
CLIENTID=$(echo $RESPONSE | jq -r '.' | awk '/ClientID/ {gsub(",","",$2);print $2}')
STATUS=$(echo $RESPONSE | jq -r '.' | awk '/Status/ {gsub(",","",$2);gsub("\"","",$2);print $2}')

### generate the test report
echo "ClientID:${CLIENTID}, Status:${STATUS}"
if [ ${STATUS} == "trusted" ]
then
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi