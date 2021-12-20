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
echo "wait for 3s"
sleep 3
# change config
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"trustDuration","value":"1m0s"}]'

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
echo "wait for 3s"
sleep 3
# get cid
echo "get client id" | tee -a ${DST}/control.txt
cid=$(awk '{ if ($1 == "clientid:") { print $2 } }' ${DST}/rac-1/config.yaml)
echo ${cid}
# get restapi auth token from echo.txt
# CONFIGRESPONSE=$(curl http://localhost:40002/config)
# echo $CONFIGRESPONSE
reporturl="http://localhost:40002/report/${cid}"
# repeat test for 3 times
TESTTIMES=3
export OLDREPORTID=0
for (( i=1; i<=${TESTTIMES}; i++ ))
do
    # do not use REPORTRESPONSE=$(curl -X GET ${reporturl}), it cost too many memory and may cause mistake
    REPORTID=$(curl -X GET ${reporturl} | jq -r '.' | awk '/ReportId/ {gsub(",","",$2);print $2}')
    echo "the newest report id is ${REPORTID}" | tee -a ${DST}/control.txt
    echo "the old report id is ${OLDREPORTID}"
    if [ "$REPORTID" -gt "$OLDREPORTID" ]
    then
        echo "${i} test successed" | tee -a ${DST}/control.txt
    else
        echo "${i} test failed" | tee -a ${DST}/control.txt
        echo "kill all test processes..." | tee -a ${DST}/control.txt
        pkill -u ${USER} ras
        pkill -u ${USER} raagent
        exit 1
    fi
    OLDREPORTID=$REPORTID
    # wait 30s for recording new report
    if [ "$i" -lt "$TESTTIMES" ] 
    then
        sleep 30
    fi
done
### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent
echo "test DONE!!!" | tee -a ${DST}/control.txt


