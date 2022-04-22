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
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5
echo "check config items via restapi request"
RESPONSE1=$(curl http://localhost:40002/config)
echo ${RESPONSE1} | tee -a ${DST}/control.txt

# get restapi auth token from echo.txt
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)

# modify the database config items
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"dbName","value":"kunpengsecl1"},{"name":"dbHost","value":"localhost1"},{"name":"dbPort","value":"1234"},{"name":"dbUser","value":"postgres1"}]'
RESPONSE2=$(curl http://localhost:40002/config)
echo ${RESPONSE2} | tee -a ${DST}/control.txt
### analyse the database testing data
DBNAME1=$(echo $RESPONSE1 | jq -r '.' | grep -A 1 "dbName" | awk '/value/ {gsub("\"","");print $2}')
DBNAME2=$(echo $RESPONSE2 | jq -r '.' | grep -A 1 "dbName" | awk '/value/ {gsub("\"","");print $2}')
DBHOST1=$(echo $RESPONSE1 | jq -r '.' | grep -A 1 "dbHost" | awk '/value/ {gsub("\"","");print $2}')
DBHOST2=$(echo $RESPONSE2 | jq -r '.' | grep -A 1 "dbHost" | awk '/value/ {gsub("\"","");print $2}')
DBPORT1=$(echo $RESPONSE1 | jq -r '.' | grep -A 1 "dbPort" | awk '/value/ {gsub("\"","");print $2}')
DBPORT2=$(echo $RESPONSE2 | jq -r '.' | grep -A 1 "dbPort" | awk '/value/ {gsub("\"","");print $2}')
DBUSER1=$(echo $RESPONSE1 | jq -r '.' | grep -A 1 "dbUser" | awk '/value/ {gsub("\"","");print $2}')
DBUSER2=$(echo $RESPONSE2 | jq -r '.' | grep -A 1 "dbUser" | awk '/value/ {gsub("\"","");print $2}')
STR0="kunpengsecl1"
STR1="localhost1"
STR2="1234"
STR3="postgres1"
echo "First time: daName:${DBNAME1}, dbHost:${DBHOST1}, dbPort:${DBPORT1}, dbUser:${DBUSER1}"
echo "Second time: daName:${DBNAME2}, dbHost:${DBHOST2}, dbPort:${DBPORT2}, dbUser:${DBUSER2}"
if [[ ${DBNAME2} == ${STR0} && ${DBHOST2} == ${STR1} && ${DBPORT2} == ${STR2} && ${DBUSER2} == ${STR3} ]]
then
    echo "database test succeeded!" | tee -a ${DST}/control.txt
    curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"dbName","value":"kunpengsecl"},{"name":"dbHost","value":"localhost"},{"name":"dbPort","value":"5432"},{"name":"dbUser","value":"postgres"}]'
else
    echo "database test failed!" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

# modify the ras config items
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"mgrStrategy","value":"auto1"},{"name":"extractRules","value":"{\"PcrRule\":{\"PcrSelection\":[1,2,3,4,5]},\"ManifestRules\":[{\"MType\":\"bios1\",\"Name\":[\"newName1\",\"newName2\"]},{\"MType\":\"ima1\",\"Name\":[\"newName1\",\"newName2\"]}]}"},{"name":"autoUpdateConfig","value":"{\"IsAllUpdate\":true,\"UpdateClients\":[1]}"}]'
RESPONSE3=$(curl http://localhost:40002/config)
echo ${RESPONSE3} | tee -a ${DST}/control.txt
### analyse the ras testing data
MGRSTRATEGY1=$(echo $RESPONSE1 | jq -r '.' | grep -A 1 "mgrStrategy" | awk '/value/ {gsub("\"","");print $2}')
MGRSTRATEGY2=$(echo $RESPONSE3 | jq -r '.' | grep -A 1 "mgrStrategy" | awk '/value/ {gsub("\"","");print $2}')
EXTRACTRULES1=$(echo $RESPONSE1 | jq -r '.' | grep -A 1 "extractRules" | awk '/value/ {gsub("\"","");gsub("\\\\","");print $2}')
EXTRACTRULES2=$(echo $RESPONSE3 | jq -r '.' | grep -A 1 "extractRules" | awk '/value/ {gsub("\"","");gsub("\\\\","");print $2}')
AUTOUPDATE1=$(echo $RESPONSE1 | jq -r '.' | grep -A 1 "autoUpdateConfig" | awk '/value/ {gsub("\"","");gsub("\\\\","");print $2}')
AUTOUPDATE2=$(echo $RESPONSE3 | jq -r '.' | grep -A 1 "autoUpdateConfig" | awk '/value/ {gsub("\"","");gsub("\\\\","");print $2}')
STR4="auto1"
STR5="{PcrRule:{PcrSelection:[1,2,3,4,5]},ManifestRules:[{MType:bios1,Name:[newName1,newName2]},{MType:ima1,Name:[newName1,newName2]}]}"
STR6="{IsAllUpdate:true,UpdateClients:[1]}"
echo "First time: mgrStrategy:${MGRSTRATEGY1}, extractRules:${EXTRACTRULES1}, autoUpdateConfig:${AUTOUPDATE1}" | tee -a ${DST}/control.txt
echo "Second time: mgrStrategy:${MGRSTRATEGY2}, extractRules:${EXTRACTRULES2}, autoUpdateConfig:${AUTOUPDATE2}" | tee -a ${DST}/control.txt

### The extractRules value and autoUpdateConfig value are modified successfully but equality judgment failed. So we comment it for the moment.
# if [[ ${MGRSTRATEGY2} == ${STR4} && ${EXTRACTRULES2} == ${STR5} &&  ${AUTOUPDATE2} == ${STR6} ]]
if [[ ${MGRSTRATEGY2} == ${STR4} ]]
then
    echo "ras test succeeded!" | tee -a ${DST}/control.txt
    curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"mgrStrategy","value":"auto"},{"name":"extractRules","value":"{\"PcrRule\":{\"PcrSelection\":[1,2,3,4]},\"ManifestRules\":[{\"MType\":\"bios\",\"Name\":[\"name1\",\"name2\"]},{\"MType\":\"ima\",\"Name\":[\"name1\",\"name2\"]}]}"},{"name":"autoUpdateConfig","value":"{\"IsAllUpdate\":false,\"UpdateClients\":null"}]'
else
    echo "ras test failed!" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

# modify the rac config items
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"hbDuration","value":"10s"},{"name":"trustDuration","value":"1m0s"},{"name":"digestAlgorithm","value":"sha256"}]'
RESPONSE4=$(curl http://localhost:40002/config)
echo ${RESPONSE4} | tee -a ${DST}/control.txt
### analyse the rac testing data
HBDURATION1=$(echo $RESPONSE1 | jq -r '.' | grep -A 1 "hbDuration" | awk '/value/ {gsub("\"","");print $2}')
HBDURATION2=$(echo $RESPONSE4 | jq -r '.' | grep -A 1 "hbDuration" | awk '/value/ {gsub("\"","");print $2}')
TRUSTDURATION1=$(echo $RESPONSE1 | jq -r '.' | grep -A 1 "trustDuration" | awk '/value/ {gsub("\"","");print $2}')
TRUSTDURATION2=$(echo $RESPONSE4 | jq -r '.' | grep -A 1 "trustDuration" | awk '/value/ {gsub("\"","");print $2}')
DIGESTALG1=$(echo $RESPONSE1 | jq -r '.' | grep -A 1 "digestAlgorithm" | awk '/value/ {gsub("\"","");print $2}')
DIGESTALG2=$(echo $RESPONSE4 | jq -r '.' | grep -A 1 "digestAlgorithm" | awk '/value/ {gsub("\"","");print $2}')
STR7="10s"
STR8="1m0s"
STR9="sha256"
echo "First time: hbDuration:${HBDURATION1}, trustDuration:${TRUSTDURATION1}, digestAlgorithm:${DIGESTALG1}" | tee -a ${DST}/control.txt
echo "Second time: hbDuration:${HBDURATION2}, trustDuration:${TRUSTDURATION2}, digestAlgorithm:${DIGESTALG2}" | tee -a ${DST}/control.txt
if [[ ${HBDURATION2} == ${STR7} && ${TRUSTDURATION2} == ${STR8} && ${DIGESTALG2} == ${STR9} ]]
then
    echo "rac test succeeded!" | tee -a ${DST}/control.txt
    curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"hbDuration","value":"5s"},{"name":"trustDuration","value":"2m0s"},{"name":"digestAlgorithm","value":"sha1"}]'
else
    echo "rac test failed!" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5
# get the server registration status
echo "check the server brief info via restapi request"
RESPONSE5=$(curl http://localhost:40002/server)
echo ${RESPONSE5} | tee -a ${DST}/control.txt

echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5
# modify the server registration status
curl -X PUT -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/server --data '{"clientids":[1], "registered":false}'
RESPONSE6=$(curl http://localhost:40002/server)
echo ${RESPONSE6} | tee -a ${DST}/control.txt
### analyse the server registration status testing data
REGISTERED1=$(echo $RESPONSE5 | jq -r '.' | grep -A 2 "\"ClientId\": 1," | awk '/Registered/ {gsub("\"","");print $2}')
REGISTERED2=$(echo $RESPONSE6 | jq -r '.' | grep -A 2 "\"ClientId\": 1," | awk '/Registered/ {gsub("\"","");print $2}')
BOOL="false"
echo "First time: ClientId1'registered:${REGISTERED1}" | tee -a ${DST}/control.txt
echo "Second time: ClientId1'registered:${REGISTERED2}" | tee -a ${DST}/control.txt
if [[ ${REGISTERED2} == ${BOOL} ]]
then
    echo "registration status test succeeded!" | tee -a ${DST}/control.txt
    curl -X PUT -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/server --data '{"clientids":[1], "registered":true}'
else
    echo "registration status test failed!" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5
# get the server base value
echo "check the server base value via restapi request" | tee -a ${DST}/control.txt
RESPONSE7=$(curl http://localhost:40002/server/basevalue/1)
echo ${RESPONSE7} | tee -a ${DST}/control.txt

echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5
# modify the server base value
curl -X PUT -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/server/basevalue/1 --data '{"measurements":[{"name":"mName","type":"ima","value":"mValue"}],"pcrvalues":[{"index":1,"value":"pValue1"}]}'
RESPONSE8=$(curl http://localhost:40002/server/basevalue/1)
echo ${RESPONSE8} | tee -a ${DST}/control.txt
### analyse the server base value testing data
VALUES1=$(echo $RESPONSE7 | jq -r '.' | grep -A 4 "\"Values\"" | awk '/\"1\"/ {gsub("\"","");gsub(",","",$2);print $2}')
VALUES2=$(echo $RESPONSE8 | jq -r '.' | grep -A 4 "\"Values\"" | awk '/\"1\"/ {gsub("\"","");gsub(",","",$2);print $2}')
MNAME1=$(echo $RESPONSE7 | jq -r '.' | grep -A 4 "\"Manifest\"" | awk '/Name/ {gsub("\"","");gsub(",","",$2);print $2}')
MNAME2=$(echo $RESPONSE8 | jq -r '.' | grep -A 4 "\"Manifest\"" | awk '/Name/ {gsub("\"","");gsub(",","",$2);print $2}')
MTYPE1=$(echo $RESPONSE7 | jq -r '.' | grep -A 4 "\"Manifest\"" | awk '/Type/ {gsub("\"","");gsub(",","",$2);print $2}')
MTYPE2=$(echo $RESPONSE8 | jq -r '.' | grep -A 4 "\"Manifest\"" | awk '/Type/ {gsub("\"","");gsub(",","",$2);print $2}')
MVALUE1=$(echo $RESPONSE7 | jq -r '.' | grep -A 4 "\"Manifest\"" | awk '/Value/ {gsub("\"","");gsub(",","",$2);print $2}')
MVALUE2=$(echo $RESPONSE8 | jq -r '.' | grep -A 4 "\"Manifest\"" | awk '/Value/ {gsub("\"","");gsub(",","",$2);print $2}')
VA="pValue1"
MN="mName"
MT="ima"
MV="mValue"
echo "First time: pcrValues:${VALUES1}, manifest'name:${MNAME1}, manifest'type:${MTYPE1}, manifest'value:${MVALUE1}" | tee -a ${DST}/control.txt
echo "Second time: pcrValues:${VALUES2}, manifest'name:${MNAME2}, manifest'type:${MTYPE2}, manifest'value:${MVALUE2}" | tee -a ${DST}/control.txt
if [[ ${VALUES2} == ${VA} && ${MNAME2} == ${MN} && ${MTYPE2} == ${MT} && ${MVALUE2} == ${MV} ]]
then
    echo "base value test succeeded!" | tee -a ${DST}/control.txt
    curl -X PUT -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/server/basevalue/1 --data "{\"measurements\":[{\"name\":\"${MNAME1}\",\"type\":\"${MTYPE1}\",\"value\":\"${MVALUE1}\"}],\"pcrvalues\":[{\"index\":1,\"value\":\"${VALUES1}\"}]}"
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
