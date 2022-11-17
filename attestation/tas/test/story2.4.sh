#!/bin.bash
### this scripts should be run under the root folder of kunpengsecl project
PROJROOT=.
REPORTGEN="Generate RA_SCENARIO_AS_WITH_DAA TA report succeeded!"
STRUUID="f68fd704-6eb1-4d14-b218-722850eb3ef0"
SAVEAKCERT="Save ak cert into tee"

# include common part
. ${PROJROOT}/attestation/tas/test/common.sh
echo "=========="
echo "start ${CASENAME} at: $(date)" | tee -a ${DST}/control.txt
echo "prepare the test environments..." | tee -a ${DST}/control.txt

echo "start akservice..." | tee -a ${DST}/control.txt
( cd ${DST}/tas ; ./akservice -T &>${DST}/tas/echo.txt ; ./akservice &>>${DST}/tas/echo.txt ; )&
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "start qca demo..." | tee -a ${DST}/control.txt
( cd ${DST}/qca ; ./qcaserver -C 2 &>${DST}/qca/echo.txt ; )&
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

S1=$(cat ${DST}/qca/echo.txt | grep "${SAVEAKCERT}")
if [ ! -z "${S1}" ]; then
    echo "save ak cert into tee succeeded" | tee -a ${DST}/control.txt
else
    echo "save ak cert into tee failed" | tee -a ${DST}/control.txt
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "start attester demo..." | tee -a ${DST}/control.txt
( cd ${DST}/attester ; ./attester -T -U ${STRUUID} &>${DST}/attester/echo.txt ; )&
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "kill all processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} akservice
pkill -u ${USER} qcaserver
pkill -u ${USER} attester
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

S2=$(cat ${DST}/qca/echo.txt | grep "${REPORTGEN}")
S3=$(cat ${DST}/qca/echo.txt | grep "${STRUUID}")
if [ ! -z "${S2}" ] && [ ! -z "${S3}" ]; then
    echo "DAA scenario report is generated for TA:${STRUUID}" | tee -a ${DST}/control.txt
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "DAA scenario report is not generated for TA:${STRUUID}" | tee -a ${DST}/control.txt
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
