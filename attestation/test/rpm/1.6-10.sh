#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
. ${PROJROOT}/attestation/test/rpm/common.sh

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt

### start ras
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ras -T &>${DST}/ras/echo.txt ; ras -v -H false &>>${DST}/ras/echo.txt ;)&
echo "wait for 3s" | tee -a ${DST}/control.txt
sleep 3
# get restapi auth token from echo.txt
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
# change config
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '{"hbduration":"5s","trustduration":"10s","ExtractRules":"{\"PcrRule\":{\"PcrSelection\":[1,2]},\"ManifestRules\":[{\"MType\":\"bios\",\"Name\":[\"8-0\",\"80000008-1\"]},{\"MType\":\"ima\",\"Name\":[\"boot_aggregate\"]}]}"}'

### start rac
echo "start rac at $(date)..." | tee -a ${DST}/control.txt
( cd ${DST}/rac ; sudo raagent -v &>${DST}/rac/echo.txt ; )&

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt
echo "wait for 3s" | tee -a ${DST}/control.txt
sleep 3

### get basevalue for testing
# get cid
echo "get client id" | tee -a ${DST}/control.txt
cid=$(awk '{ if ($1 == "clientid:") { print $2 } }' ${HOMERACCONF}/config.yaml)
echo ${cid} | tee -a ${DST}/control.txt
# CONFIGRESPONSE=$(curl http://localhost:40002/config)
# echo $CONFIGRESPONSE
basevalueurl="http://localhost:40002/${cid}/basevalues"
# get newest basevalue id
basevalueid1=$(curl -H "Content-Type: application/json" ${basevalueurl} | jq -r '.' | grep -A 0 "ID" | grep -v "ClientID\|--"  | awk '{gsub(",","",$2);print $2}' | tail -n 1)
basevalueurl1="http://localhost:40002/${cid}/basevalues/${basevalueid1}"
### test base value extract
## test pcr extract
# get extracted pcrs
bpcr=$(curl -H "Content-Type: application/json" ${basevalueurl1} | jq -r '.' | grep -A 0 "Pcr" | awk -F '"' '{print$4}' )
# test not extracted pcr
bpcr1=$(echo -e ${bpcr} | grep "^1")
bpcr3=$(echo -e ${bpcr} | grep "^3")
if [ ! -z "${bpcr1}"  ] && [ -z "${bpcr3}" ]
then
    echo "test 1: pcr base value extract successed" | tee -a ${DST}/control.txt
else
    echo "test 1: base value extract failed" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

## test manifest extract
bbios1=$(curl -H "Content-Type: application/json" ${basevalueurl1} | jq -r '.' | grep "80000008-1")
bbios2=$(curl -H "Content-Type: application/json" ${basevalueurl1} | jq -r '.' | grep "80000000-1")
bima1=$(curl -H "Content-Type: application/json" ${basevalueurl1} | jq -r '.' | grep "boot_aggregate")
bima2=$(curl -H "Content-Type: application/json" ${basevalueurl1} | jq -r '.' | grep "/etc/modprobe.d/tuned.conf")
# the length of rima1 and bima1 is different, use =~
if [ ! -z "${bbios1}" ] && [ -z "${bbios2}" ] && [ ! -z "${bima1}" ] && [ -z "${bima2}" ]
then
    echo "test 2: manifest base value extract successed" | tee -a ${DST}/control.txt
else
    echo "test 2: manifest base value extract failed" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

### test auto update
# set isallupdate as true in config
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '{"isallupdate":true}'
echo "test 3: mode is auto now" | tee -a ${DST}/control.txt
# modify ima file
OLDLINE="10 6fefbefdf63fbc4210a8eee66a21a63e578300d6 ima 1b8ccbdcaac1956b7c48529efbfb32e76355b1ca boot_aggregate"
NEWLINE="10 88ff8c85e6b94cbf8002a17fd59f1ea1bd13ecc4 ima 2b8ccbdcaac1956b7c48529efbfb32e76355b1ca boot_aggregate"
sed -i --follow-symlinks "s/${OLDLINE}/${NEWLINE}/g" ${IMAFILE}
# wait for 20s
echo "test 3: modified ima file, wait 20s for updating report and base value" | tee -a ${DST}/control.txt
sleep 20
basevalueid2=$(curl -H "Content-Type: application/json" ${basevalueurl} | jq -r '.' | grep -A 0 "ID" | grep -v "ClientID\|--"  | awk '{gsub(",","",$2);print $2}' | tail -n 1)
basevalueurl2="http://localhost:40002/${cid}/basevalues/${basevalueid2}"
bima2=$(curl -H "Content-Type: application/json" ${basevalueurl2} | jq -r '.' | grep "boot_aggregate")
# base value should be different with test2
if [ "${bima2}" != "${bima1}" ]
then
    echo "test 3: auto update successed" | tee -a ${DST}/control.txt
else
    echo "test 3: auto update failed" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

# set isallupdate as false and set client autoupdate in config
# notice: now for make test simple, make its list as [1] because we just test one client
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '{"isallupdate":false}'
echo "test 4: isallupdate is false, updateClients is [1] now" | tee -a ${DST}/control.txt
# modify ima file
sed -i --follow-symlinks "s/${NEWLINE}/${OLDLINE}/g" ${IMAFILE}
# set client 1 as auto update
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/${cid} --data '{"isautoupdate":true}'
echo $(curl -H "Content-Type: application/json" http://localhost:40002/${cid})
# wait for 20s
echo "test 4: modified ima file, wait 20s for updating report and base value" | tee -a ${DST}/control.txt
sleep 20
basevalueid3=$(curl -H "Content-Type: application/json" ${basevalueurl} | jq -r '.' | grep -A 0 "ID" | grep -v "ClientID\|--"  | awk '{gsub(",","",$2);print $2}' | tail -n 1)
basevalueurl3="http://localhost:40002/${cid}/basevalues/${basevalueid3}"
bima3=$(curl -H "Content-Type: application/json" ${basevalueurl3} | jq -r '.' | grep "boot_aggregate")
if [ "${bima3}" != "${bima2}" ]
then
    echo "test 4: auto update(isallupdate:false, updateClient:[1]) successed" | tee -a ${DST}/control.txt
else
    echo "test 4: auto update(isallupdate:false, updateClient:[1]) failed" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

# set isallupdate as false in config
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '{"isallupdate":false}'
echo "test 5: modified ima file, wait 20s to see if the basevale will update" | tee -a ${DST}/control.txt
# modify ima file
sed -i --follow-symlinks "s/${OLDLINE}/${NEWLINE}/g" ${IMAFILE}
# set client 1 as not auto update
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/${cid} --data '{"isautoupdate":false}'
# wait for 20s
echo "test 5: modified ima file, wait 20s to see if the base value will be updated" | tee -a ${DST}/control.txt
sleep 20
basevalueid4=$(curl -H "Content-Type: application/json" ${basevalueurl} | jq -r '.' | grep -A 0 "ID" | grep -v "ClientID\|--"  | awk '{gsub(",","",$2);print $2}' | tail -n 1)
basevalueurl4="http://localhost:40002/${cid}/basevalues/${basevalueid4}"
bima4=$(curl -H "Content-Type: application/json" ${basevalueurl4} | jq -r '.' | grep "boot_aggregate")
if [ "${bima4}" == "${bima3}" ]
then
    echo "test 5: not auto update successed" | tee -a ${DST}/control.txt
else
    echo "test 5: not auto update failed" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent

echo "test SUCCEEDED!!!" | tee -a ${DST}/control.txt
exit 0
