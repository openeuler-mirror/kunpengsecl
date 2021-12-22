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
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"trustDuration","value":"1m0s"},{"name":"extractRules","value":"{\"PcrRule\":{\"PcrSelection\":[0,1]},\"ManifestRules\":[{\"MType\":\"bios\",\"Name\":[\"8-0\",\"80000008-1\"]},{\"MType\":\"ima\",\"Name\":[\"boot_aggregate\",\"/etc/modprobe.d/tuned.conf\"]}]}"}]'

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
basevalueurl="http://localhost:40002/server/basevalue/${cid}"

### test base value extract
## test pcr extract
# test extracted pcr
rpcr0=$(curl -X GET ${reporturl} | jq -r '.' | grep "\"0\":")
bpcr0=$(curl -X GET ${basevalueurl} | jq -r '.' | grep "\"0\":")
# test not extracted pcr
rpcr2=$(curl -X GET ${reporturl} | jq -r '.' | grep "\"2\":")
bpcr2=$(curl -X GET ${basevalueurl} | jq -r '.' | grep "\"2\":")
if [ "$rpcr0" == "$bpcr0" ] && [ "$bpcr2" != "$rpcr2" ]
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
rbios1=$(curl -X GET ${reporturl} | jq -r '.' | grep "\"80000008-1\":")
bbios1=$(curl -X GET ${basevalueurl} | jq -r '.' | grep "\"80000008-1\":")
rima1=$(curl -X GET ${reporturl} | jq -r '.' | grep -A 1 "\"\/etc\/modprobe.d\/tuned.conf\"," | grep "Value")
bima1=$(curl -X GET ${basevalueurl} | jq -r '.' | grep -A 1 "\"\/etc/modprobe.d\/tuned.conf\"," | grep "Value")
rbios2=$(curl -X GET ${reporturl} | jq -r '.' | grep "\"80000001-2\":")
bbios2=$(curl -X GET ${basevalueurl} | jq -r '.' | grep "\"80000001-2\":")
# the length of rima1 and bima1 is different, use =~
if [ "$rpcr0" == "$bpcr0" ] && [ "$bpcr2" != "$rpcr2" ] && [[ "$rima1" =~ "$bima1" ]]
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
# set autoUpdate as true in config
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"mgrStrategy","value":"auto-update"},{"name":"autoUpdateConfig","value":"{\"IsAllUpdate\":true,\"UpdateClients\":null}"}]'
echo "test 3: mode is auto update now" | tee -a ${DST}/control.txt
# modify ima file
OLDLINE="10 6fefbefdf63fbc4210a8eee66a21a63e578300d6 ima 1b8ccbdcaac1956b7c48529efbfb32e76355b1ca \/etc\/modprobe.d\/tuned.conf"
NEWLINE="10 88ff8c85e6b94cbf8002a17fd59f1ea1bd13ecc4 ima 2b8ccbdcaac1956b7c48529efbfb32e76355b1ca \/etc\/modprobe.d\/tuned.conf"
sed -i --follow-symlinks "s/${OLDLINE}/${NEWLINE}/g" ${RACDIR}/${IMAFILE}
# wait for 30s
echo "test 3: modified ima file, wait 30s for updating report and base value" | tee -a ${DST}/control.txt
sleep 30
rima2=$(curl -X GET ${reporturl} | jq -r '.' | grep -A 1 "\"\/etc\/modprobe.d\/tuned.conf\"," | grep "Value")
bima2=$(curl -X GET ${basevalueurl} | jq -r '.' | grep -A 1 "\"\/etc/modprobe.d\/tuned.conf\"," | grep "Value")
# report should be different with test2 and base value should change 
if [ "$rima2" != "$rima1" ] && [[ "$rima2" =~ "$bima2" ]]
then
    echo "test 3: auto update(isAllUpdate:true) successed" | tee -a ${DST}/control.txt
else
    echo "test 3: auto update(isAllUpdate:true) failed" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

# set autoUpdate as false and set update-clients null in config
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"mgrStrategy","value":"auto-update"},{"name":"autoUpdateConfig","value":"{\"IsAllUpdate\":false,\"UpdateClients\":null}"}]'
echo "test 4: IsAllUpdate is false, updateClients is null now" | tee -a ${DST}/control.txt
# modify ima file
sed -i --follow-symlinks "s/${NEWLINE}/${OLDLINE}/g" ${RACDIR}/${IMAFILE}
# wait for 30s
echo "test 4: modified ima file, wait 30s for updating report and base value" | tee -a ${DST}/control.txt
sleep 30
rima3=$(curl -X GET ${reporturl} | jq -r '.' | grep -A 1 "\"\/etc\/modprobe.d\/tuned.conf\"," | grep "Value")
bima3=$(curl -X GET ${basevalueurl} | jq -r '.' | grep -A 1 "\"\/etc/modprobe.d\/tuned.conf\"," | grep "Value")
# base value should be the same as test3 and report should change
if [ "$bima3" == "$bima2" ] && [[ "$rima3" != "$rima2" ]]
then
    echo "test 4: auto update(isAllUpdate:false, updateClient:null) successed" | tee -a ${DST}/control.txt
else
    echo "test 4: auto update(isAllUpdate:false, updateClient:null) failed" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

# set autoUpdate as false and set update-clients right in config
# notice: now for make test simple, make its list as [1] because we just test one client
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"mgrStrategy","value":"auto-update"},{"name":"autoUpdateConfig","value":"{\"IsAllUpdate\":false,\"UpdateClients\":[1]}"}]'
echo "test 5: IsAllUpdate is false, updateClients is [1] now" | tee -a ${DST}/control.txt
# modify ima file
sed -i --follow-symlinks "s/${OLDLINE}/${NEWLINE}/g" ${RACDIR}/${IMAFILE}
# wait for 30s
echo "test 5: modified ima file, wait 30s for updating report and base value" | tee -a ${DST}/control.txt
sleep 30
rima4=$(curl -X GET ${reporturl} | jq -r '.' | grep -A 1 "\"\/etc\/modprobe.d\/tuned.conf\"," | grep "Value")
bima4=$(curl -X GET ${basevalueurl} | jq -r '.' | grep -A 1 "\"\/etc/modprobe.d\/tuned.conf\"," | grep "Value")
if [ "$rima4" != "$rima3" ] && [[ "$rima4" =~ "$bima4" ]]
then
    echo "test 5: auto update(isAllUpdate:false, updateClient:[1]) successed" | tee -a ${DST}/control.txt
else
    echo "test 5: auto update(isAllUpdate:false, updateClient:[1]) failed" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

# set mgrStrategy as auto in config
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"mgrStrategy","value":"auto"}]'
echo "test 6: mgrStrategy is auto now" | tee -a ${DST}/control.txt
# modify ima file
sed -i --follow-symlinks "s/${NEWLINE}/${OLDLINE}/g" ${RACDIR}/${IMAFILE}
# wait for 30s
echo "test 6: modified ima file, wait 30s for updating report and base value" | tee -a ${DST}/control.txt
sleep 30
rima5=$(curl -X GET ${reporturl} | jq -r '.' | grep -A 1 "\"\/etc\/modprobe.d\/tuned.conf\"," | grep "Value")
bima5=$(curl -X GET ${basevalueurl} | jq -r '.' | grep -A 1 "\"\/etc/modprobe.d\/tuned.conf\"," | grep "Value")
if [ "$rima5" != "$rima4" ] && [[ "$bima5" == "$bima4" ]]
then
    echo "test 6: auto update(mgrStrategy: auto) successed" | tee -a ${DST}/control.txt
else
    echo "test 6: auto update(mgrStrategy: auto) failed" | tee -a ${DST}/control.txt
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
echo "test DONE!!!" | tee -a ${DST}/control.txt
exit 0

