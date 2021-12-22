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
echo "start to perform test ..." | tee -a ${DST}/control.txt
echo "wait for 30s"
sleep 30

# read the running logs of ras and rac to determine whether the registration is successful
# get cid
clientID1=$(cat ${DST}/rac-$((i-1))/echo.txt | awk '/clientID=/ {gsub("clientID=","",$7);print $7}')
# get ras/rac's config of HBDuration and TrustDuration, check if the configuration of rac has been updated
rasHBD=$(awk '{ if ($1 == "hbduration:") { print $2 } }' ${DST}/ras/config.yaml)
racHBD=$(awk '{ if ($1 == "hbduration:") { print $2 } }' ${DST}/rac-1/config.yaml)
rasTD=$(awk '{ if ($1 == "trustduration:") { print $2 } }' ${DST}/ras/config.yaml)
racTD=$(awk '{ if ($1 == "trustduration:") { print $2 } }' ${DST}/rac-1/config.yaml)
if [ ${clientID1} != "" ] && [ ${rasHBD} == ${racHBD} ] && [ ${rasTD} == ${racTD} ]
then
    echo "RegisterClient succeeded! clientID=${clientID1}" | tee -a ${DST}/control.txt
    echo "rac's hbduration has been set as ${racHBD}" | tee -a ${DST}/control.txt
    echo "rac's trustduration has been set as ${racTD}" | tee -a ${DST}/control.txt
else
    echo "RegisterClient failed!" | tee -a ${DST}/control.txt
fi

# kill rac
pkill -u ${USER} raagent

# restart number of rac clients
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

# Read the running log of ras and rac to see if it will re-register
echo "wait for 30s"
sleep 30
clientID2=$(cat ${DST}/rac-$((i-1))/echo.txt | awk '/clientID=/ {gsub("clientID=","",$7);print $7}')
if [ "${clientID2}" != "" ]
then
    echo "register again!" | tee -a ${DST}/control.txt
else
    echo "No re-registration!" | tee -a ${DST}/control.txt
fi

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent

echo "test DONE!!!" | tee -a ${DST}/control.txt


### generate the test report
if [ ${clientID1} != "" ] && [ ${clientID2} == "" ]
then
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
