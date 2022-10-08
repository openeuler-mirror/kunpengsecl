#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
. ${PROJROOT}/attestation/test/rpm/common.sh

### start ras
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ras -T &>${DST}/ras/echo.txt ; ras -v -H false &>>${DST}/ras/echo.txt ;)&

### start rac
echo "start rac at $(date)..." | tee -a ${DST}/control.txt
( cd ${DST}/rac ; sudo raagent -v &>${DST}/rac/echo.txt ; )&
echo "wait for 5s"
sleep 5

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5

# read the running logs of ras and rac to determine whether the registration is successful
# get cid
clientID1=$(cat ${DST}/rac/echo.txt | awk '/clientID=/ {gsub("clientID=","",$4);print $4}')
# get ras/rac's config of HBDuration and TrustDuration, check if the configuration of rac has been updated
rasHBD=$(awk '{ if ($1 == "hbduration:") { print $2 } }' ${HOMERASCONF}/config.yaml)
racHBD=$(awk '{ if ($1 == "hbduration:") { print $2 } }' ${HOMERACCONF}/config.yaml)
rasTD=$(awk '{ if ($1 == "trustduration:") { print $2 } }' ${HOMERASCONF}/config.yaml)
racTD=$(awk '{ if ($1 == "trustduration:") { print $2 } }' ${HOMERACCONF}/config.yaml)
if [ "${clientID1}" != "" ] && [ "${rasHBD}" == "${racHBD}" ] && [ "${rasTD}" == "${racTD}" ]
then
    echo "RegisterClient succeeded! clientID=${clientID1}" | tee -a ${DST}/control.txt
    echo "rac's hbduration has been set as ${racHBD}" | tee -a ${DST}/control.txt
    echo "rac's trustduration has been set as ${racTD}" | tee -a ${DST}/control.txt
else
    echo "RegisterClient failed!" | tee -a ${DST}/control.txt
fi

# kill rac
pkill -u ${USER} raagent

### restart rac
echo "start rac at $(date)..." | tee -a ${DST}/control.txt
( cd ${DST}/rac ; sudo raagent -v &>${DST}/rac/echo.txt ; )&
echo "wait for 5s"
sleep 5

# Read the running log of ras and rac to see if it will re-register
clientID2=$(cat ${DST}/rac/echo.txt | awk '/clientID=/ {gsub("clientID=","",$4);print $4}')
if [ "${clientID2}" != "${clientID1}" ]
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
if [ "${clientID1}" != "" ] && [ "${clientID2}" == "${clientID1}" ]
then
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
