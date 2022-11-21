#!/bin.bash
### this scripts should be run under the root folder of kunpengsecl project
PROJROOT=.
NEWVALUE="test value"

# include common part
. ${PROJROOT}/attestation/tas/test/common.sh
echo "=========="
echo "start ${CASENAME} at: $(date)" | tee -a ${DST}/control.txt
echo "prepare the test environments..." | tee -a ${DST}/control.txt

# get authtoken value to use POST method
( cd ${DST}/tas ; ./akservice -T &>${DST}/tas/echo.txt ; )&
echo "get authtoken value..." | tee -a ${DST}/control.txt
sleep 1
AUTHTOKEN=$(grep "Bearer " ${DST}/tas/echo.txt)
if [ -z "${AUTHTOKEN}" ]; then
    echo "get authtoken value failed" | tee -a ${DST}/control.txt
    echo "test failed!" | tee -a ${DST}/control.txt
    pkill -u ${USER} akservice
    exit 1
fi
echo "get authtoken value succeeded" | tee -a ${DST}/control.txt
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "start akservice..." | tee -a ${DST}/control.txt
( cd ${DST}/tas ; ./akservice &>>${DST}/tas/echo.txt ; )&
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

# get default base value
echo "get default base value..." | tee -a ${DST}/control.txt
DEFAULTVALUE=$(curl -X GET -H "Content-Type: application/json" http://localhost:40009/config | jq -r '.' | awk -F '"' '/basevalue/ {print $4}')
if [ -z "${DEFAULTVALUE}" ]; then
    echo "get default base value failed" | tee -a ${DST}/control.txt
    echo "test failed!" | tee -a ${DST}/control.txt
    pkill -u ${USER} akservice
    exit 1
fi
echo "get default base value succeeded" | tee -a ${DST}/control.txt
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "kill ak service process..." | tee -a ${DST}/control.txt
pkill -u ${USER} akservice
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "re-start akservice..." | tee -a ${DST}/control.txt
( cd ${DST}/tas ; ./akservice &>>${DST}/tas/echo.txt ; )&
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

BV1=$(curl -X GET -H "Content-Type: application/json" http://localhost:40009/config | jq -r '.' | awk -F '"' '/basevalue/ {print $4}')
if [ "${BV1}" = "${DEFAULTVALUE}"  ]; then
    echo "check base value is right" | tee -a ${DST}/control.txt
else
    echo "check base value is wrong" | tee -a ${DST}/control.txt
    echo "test failed!" | tee -a ${DST}/control.txt
    pkill -u ${USER} akservice
    exit 1
fi
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "modify base value to: ${NEWVALUE}" | tee -a ${DST}/control.txt
curl -X POST -H "Content-Type: application/json" -H "Authorization: ${AUTHTOKEN}" -d "{\"basevalue\":\"${NEWVALUE}\"}" http://localhost:40009/config
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

BV2=$(curl -X GET -H "Content-Type: application/json" http://localhost:40009/config | jq -r '.' | awk -F '"' '/basevalue/ {print $4}')
if [ "${BV2}" = "${NEWVALUE}" ]; then
    echo "modify base value to: \"${NEWVALUE}\" succeeded" | tee -a ${DST}/control.txt
    echo "test succeeded!" | tee -a ${DST}/control.txt
    pkill -u ${USER} akservice
    exit 0
else
    echo "modify base value to: \"${NEWVALUE}\" failed" | tee -a ${DST}/control.txt
    echo "test failed!" | tee -a ${DST}/control.txt
    pkill -u ${USER} akservice
    exit 1
fi
