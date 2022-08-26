#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
# run number of rac clients to test
NUM=1
# include common part
. ${PROJROOT}/attestation/test/integration/common.sh
. ${PROJROOT}/attestation/test/integration/1.x.common.sh
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
### Here we launch in https mode
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ./ras -T &>${DST}/ras/echo.txt ; ./ras -v &>>${DST}/ras/echo.txt ;)&
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)

### start number of rac clients
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t -v &>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5

# get cid
echo "get client id..." | tee -a ${DST}/control.txt
cid=$(awk '{ if ($1 == "clientid:") { print $2 } }' ${DST}/rac-1/config.yaml)
echo ${cid} | tee -a ${DST}/control.txt

# query the client registration status
echo "query registration status of ${cid}..." | tee -a ${DST}/control.txt
NODEINFO1=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid})
RSTATUS1=$(echo $NODEINFO1 | jq -r '.' | awk '/registered/ {gsub(",","");print $2}')
echo "query succeeded!" | tee -a ${DST}/control.txt
# modify the client registration status
echo "modify registration status of ${cid} to false..." | tee -a ${DST}/control.txt
curl -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" -d '{"registered":false}' https://localhost:40003/${cid}
echo "modify succeeded!" | tee -a ${DST}/control.txt
NODEINFO2=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid})
RSTATUS2=$(echo $NODEINFO2 | jq -r '.' | awk '/registered/ {gsub(",","");print $2}')
### analyse the client registration status testing data
echo "First time: Client:${cid} registered:${RSTATUS1}" | tee -a ${DST}/control.txt
echo "Second time: Client:${cid} registered:${RSTATUS2}" | tee -a ${DST}/control.txt
if [[ ${RSTATUS2} == ${NONREGISTER} ]]
then
    echo "registration status test succeeded!" | tee -a ${DST}/control.txt
    echo "start recovering registration status..." | tee -a ${DST}/control.txt
    curl -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" -d '{"registered":true}' https://localhost:40003/${cid}
    sleep 5
    echo "registration status recover succeeded!" | tee -a ${DST}/control.txt
else
    echo "registration status test failed!" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

sleep 5
# add a new base value to the client
echo "add a new base value to client:${cid}..." | tee -a ${DST}/control.txt
curl -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" -d "{\"name\":\"mytestBValue\", \"enabled\":true, \
        \"pcr\":\"${strPCR}\", \"bios\":\"${strBIOS}\", \"ima\":\"${strIMA}\", \"isnewgroup\":true}" \
            https://localhost:40003/${cid}/newbasevalue
sleep 2
BASEVALUES=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues)
bid=$(echo ${BASEVALUES} | jq -r '.' | grep -B 6 "mytestBValue" | awk '/"ID"/ {gsub(",","");print $2}')
BVALUEDETAILS1=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues/${bid})
# modify "Enabled" field of the specific base value to false
echo "modify base value of client:${cid}..." | tee -a ${DST}/control.txt
curl -X POST -k -H "Authorization: $AUTHTOKEN" -H "Content-type: application/json" https://localhost:40003/${cid}/basevalues/${bid} --data '{"enabled":false}'
BVALUEDETAILS2=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues/${bid})
# delete base value added before
echo "delete base value of client:${cid}..." | tee -a ${DST}/control.txt
curl -X DELETE -k -H "Authorization: $AUTHTOKEN" -H "Content-type: application/json" https://localhost:40003/${cid}/basevalues/${bid}
BASEVALUES2=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues)
ISEXIST=$(echo $BASEVALUES2 | jq -r '.' | awk '/"ID"/ {gsub(",","",$2);print $2}' | grep ${bid})
### analyse the base value testing data
ENABLED1=$(echo $BVALUEDETAILS1 | jq -r '.' | awk '/Enabled/ {gsub(",","",$2);print $2}')
ENABLED2=$(echo $BVALUEDETAILS2 | jq -r '.' | awk '/Enabled/ {gsub(",","",$2);print $2}')
echo "First time: Enabled:${ENABLED1}" | tee -a ${DST}/control.txt
echo "Second time: Enabled:${ENABLED2}" | tee -a ${DST}/control.txt
if [[ ${ENABLED1} == true && ${ENABLED2} == false && -z ${ISEXIST} ]]
then
    echo "base value test succeeded!" | tee -a ${DST}/control.txt
    sleep 5
else
    echo "base value test failed!" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

### stop test
echo "all test succeeded!" | tee -a ${DST}/control.txt
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent
echo "test DONE!!!" | tee -a ${DST}/control.txt
exit 0