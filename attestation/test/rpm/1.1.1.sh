#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
. ${PROJROOT}/attestation/test/rpm/common.sh

### start ras
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ras -T &>${DST}/ras/echo.txt ; ras -v &>>${DST}/ras/echo.txt ;)&

### start rac
echo "start rac at $(date)..." | tee -a ${DST}/control.txt
( cd ${DST}/rac ; sudo raagent -v &>${DST}/rac/echo.txt ; )&
echo "wait for 5s"
sleep 5

### restart rac
echo "kill all test processes of rac..." | tee -a ${DST}/control.txt
pkill -u ${USER} raagent
echo "start rac at $(date)..." | tee -a ${DST}/control.txt
( sudo raagent -v &>>${DST}/rac/echo.txt ; )&
echo "wait for 5s"
sleep 5

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent

### log analyse
### check the ekCert's log is only one
ECCOUNT=$(grep 'load EK certificate success' ${DST}/rac/echo.txt | wc -l)
echo "generateEKCert count: ${ECCOUNT}" | tee -a ${DST}/control.txt
### check the ekCert's file is not null
if test -s ${HOMERACCONF}/ec.crt;then
    ECEMPTY=0
    echo "ec is not empty" | tee -a ${DST}/control.txt
else
    ECEMPTY=1
    echo "ec is empty" | tee -a ${DST}/control.txt
fi
### check the ikCert's log is only one
ICCOUNT=$(grep 'load IK certificate success' ${DST}/rac/echo.txt | wc -l)
echo "generateIKCert count: ${ICCOUNT}" | tee -a ${DST}/control.txt
### check the ikCert's file is not null
if test -s ${HOMERACCONF}/ic.crt;then
    ICEMPTY=0
    echo "ic is not empty" | tee -a ${DST}/control.txt
else
    ICEMPTY=1
    echo "ic is empty" | tee -a ${DST}/control.txt
fi

if (( ${ECCOUNT} == 1 )) && (( ${ICCOUNT} == 1 )) && (( ${ECEMPTY} == 0 )) && (( ${ICEMPTY} == 0 ))
then
    echo "test succeeded!"
    exit 0
else
    echo "test failed!"
    exit 1
fi