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

### define some constant
strUUID="9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9"
strCONTAINER="container"
strNAME="testContainer"

### start launching binaries for testing
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ./ras -T &>${DST}/ras/echo.txt ; ./ras -v &>>${DST}/ras/echo.txt ;)&
echo "sleep 5s" | tee -a ${DST}/control.txt
sleep 5

# start number of rac 
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t -v &>>${DST}/rac-${i}/echo.txt ; )&
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

# get cid
echo "get client id" | tee -a ${DST}/control.txt
cid=$(awk '{ if ($1 == "clientid:") { print $2 } }' ${DST}/rac-1/config.yaml)
echo ${cid} | tee -a ${DST}/control.txt

# get the container information for the first time
RESPONSE1=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues)
CONTAINERINFO1=$(echo ${RESPONSE1} | jq -r '.' | grep ${strUUID})
if [ -z "$CONTAINERINFO1" ]
then
    echo "first query..." | tee -a ${DST}/control.txt
    echo "the container named ${strNAME} does not exist." | tee -a ${DST}/control.txt
    echo "take the next step..." | tee -a ${DST}/control.txt
else
    echo "the container named ${strNAME} does exist." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5

# add container basevalue
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
echo "start adding new container basevalue which uuid is ${strUUID}..." | tee -a ${DST}/control.txt
curl -X POST -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" https://localhost:40003/${cid}/newbasevalue --data "{\"uuid\":\"${strUUID}\", \"basetype\":\"${strCONTAINER}\", \"name\":\"${strNAME}\", \"enabled\":true}"
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5


# get the container information for the second time
RESPONSE2=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues)
CONTAINERINFO2=$(echo ${RESPONSE2} | jq -r '.' | grep ${strUUID})
if [ -n "$CONTAINERINFO2" ]
then
    echo "second query..." | tee -a ${DST}/control.txt
    echo "the container named ${strNAME} does exist." | tee -a ${DST}/control.txt
    echo "take the next step..." | tee -a ${DST}/control.txt
else
    echo "the container named ${strNAME} does not exist." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5

# get bid
echo "get basevalue id" | tee -a ${DST}/control.txt
bid=$(echo ${RESPONSE2} | jq -r '.' | grep -B 3 ${strUUID} | awk '/"ID"/ {gsub(",","",$2);print $2}')
echo ${bid} | tee -a ${DST}/control.txt

# delete the container
echo "start deleting container basevalue which uuid is ${strUUID}..." | tee -a ${DST}/control.txt
curl -X DELETE -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues/${bid}
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5

# get the container information for the third time
RESPONSE3=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues)
CONTAINERINFO3=$(echo ${RESPONSE3} | jq -r '.' | grep ${strUUID})
if [ -z "$CONTAINERINFO3" ]
then
    echo "third query..." | tee -a ${DST}/control.txt
    echo "the container named ${strNAME} does not exist." | tee -a ${DST}/control.txt
    echo "take the next step..." | tee -a ${DST}/control.txt
else
    echo "the container named ${strNAME} does exist." | tee -a ${DST}/control.txt
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
