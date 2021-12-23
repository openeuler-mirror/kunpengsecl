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
sed -i --follow-symlinks "s/trustduration: 2m0s/trustduration: 20s/g" ${DST}/ras/config.yaml
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
# stop rac
echo "kill all raagent processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} raagent

# modify ima file
NEWLINE1="10 5a2842c1767f26defc2e96a01e46062524333501 ima 732458574c63c3790cad093a36eadfb990d11ee6 /var/lib/docker/containers/9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9/hosts"
NEWLINE2="10 8c4c4953a4cc0b1a73ee54fcc72540a6834e8f49 ima 186d209e1d331e9160d6d0b03c523d862ae9d2a4 /var/lib/docker/containers/9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9/resolv.conf"
echo "${NEWLINE1}" >> ${RACDIR}/${IMAFILE}
echo "${NEWLINE2}" >> ${RACDIR}/${IMAFILE}

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

# register container
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/container/9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9 --data '{"registered":true,"serverid":1,"uuid":"9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9"}'

# post basevalue
echo "post basevalue ing..." | tee -a ${DST}/control.txt
curl -X PUT -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/container/basevalue/9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9 --data '{"measurements":[{"name":"/var/lib/docker/containers/9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9/hosts","type":"ima","value":"732458574c63c3790cad093a36eadfb990d11ee6"},{"name":"/var/lib/docker/containers/9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9/resolv.conf","type":"ima","value":"186d209e1d331e9160d6d0b03c523d862ae9d2a4"}]}'

echo "wait for 15s" | tee -a ${DST}/control.txt
sleep 15

# get-response
RESPONSE=$(curl http://localhost:40002/container/status)
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
echo "ClientID:${CLIENTID}, Status:${STATUS}" | tee -a ${DST}/control.txt
if [ ${STATUS} == "trusted" ]
then
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi