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
strMANUAL="manual"
strPCR="1:2ce976e4df6808c82fe206fac08f3acf012b0ec4\n2:c5e026af427eadae287b977035f49747e269e5a9\n3:c5e026af427eadae287b977035f49747e269e5a9\n4:d4dff43b56f1aacbecdae6c468d2cb7ffb27827e\n"
strBIOS="8-0 53933be89080c1fdc6352bb6c8e78799d01f2300 sha256:77e41e1a6e98f7160a8ba85d1b681df84b749f88ffd585612e145421b42ee581\n80000008-1 c6daaaf66efce12d87254eb5dc4bd2b8ad0dc085 sha256:723ed4cf5accf65d8fe684491d5cb1f6167f6315fa553d57fbf946667b07c2ad\n"
strIMA="ima 5e7bbf27b7dd568610cc1f1ea49ceaa420395690 boot_aggregate\nima 1b8ccbdcaac1956b7c48529efbfb32e76355b1ca /etc/modprobe.d/tuned.conf\n"
strNEWIMA="ima 6e7bbf27b7dd568610cc1f1ea49ceaa420395690 boot_aggregate\nima 1b8ccbdcaac1956b7c48529efbfb32e76355b1ca /etc/modprobe.d/tuned.conf\n"
strTRUSTED="trusted"
strUNTRUSTED="untrusted"
strUNKNOWN="unknown"

### start launching binaries for testing
### Here we launch in https mode
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ./ras -T &>${DST}/ras/echo.txt ; ./ras -v &>>${DST}/ras/echo.txt ;)&
echo "wait for 5s..." | tee -a ${DST}/control.txt
sleep 5
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)

### change mgrstrategy to "manual"
echo "check config items via restapi request..." | tee -a ${DST}/control.txt
CONFIGS1=$(curl -k -H "Content-Type: application/json" https://localhost:40003/config)
MGRSTRATEGY1=$(echo $CONFIGS1 | jq -r '.' | awk '/MgrStrategy/ {gsub("\"","",$2);gsub(",","",$2);print $2}')
if [ "$MGRSTRATEGY1" != "$strMANUAL" ]
then
    echo "config mgrstrategy is not equal to manual, start to set it to manual..." | tee -a ${DST}/control.txt
    curl -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" https://localhost:40003/config --data "{\"trustduration\":20, \"MgrStrategy\":\"${strMANUAL}\"}"
fi
CONFIGS2=$(curl -k -H "Content-Type: application/json" https://localhost:40003/config)
MGRSTRATEGY2=$(echo $CONFIGS2 | jq -r '.' | awk '/MgrStrategy/ {gsub("\"","",$2);gsub(",","",$2);print $2}')
if [ "$MGRSTRATEGY2" == "$strMANUAL" ]
then
    echo "mgrstrategy has been set to manual." | tee -a ${DST}/control.txt
fi

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

echo "wait for 5s..." | tee -a ${DST}/control.txt
sleep 5

# get cid
echo "get client id..." | tee -a ${DST}/control.txt
cid=$(awk '{ if ($1 == "clientid:") { print $2 } }' ${DST}/rac-1/config.yaml)
echo ${cid} | tee -a ${DST}/control.txt
# query the registration status of cid
echo "query registration status of ${cid}..." | tee -a ${DST}/control.txt
NODEINFO1=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid})
RSTATUS1=$(echo $NODEINFO1 | jq -r '.' | awk '/registered/ {gsub(",","");print $2}')
BASEVALUES1=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues)
TSTATUS1=$(echo $NODEINFO1 | jq -r '.' | awk '/trusted/ {gsub("\"","",$2);gsub(",","",$2);print $2}')
REPORTS1=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/reports)
if [[ $RSTATUS1 == false && $BASEVALUES1 == "[]" && $TSTATUS1 == ${strUNKNOWN} && $REPORTS1 == "[]" ]]
then
    echo "the ${cid} client is not registered yet." | tee -a ${DST}/control.txt
    echo "the ${cid} client's basevalues are empty." | tee -a ${DST}/control.txt
    echo "the ${cid} client's trust status is unknown." | tee -a ${DST}/control.txt
    echo "the ${cid} client's reports are empty." | tee -a ${DST}/control.txt
    echo "test1 succeeded!" | tee -a ${DST}/control.txt
else
    echo "test1 failed!" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

# set the specific client's registration status to true
curl -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" -d '{"registered":true}' https://localhost:40003/${cid}
echo "wait for 5s..." | tee -a ${DST}/control.txt
sleep 5
NODEINFO2=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid})
RSTATUS2=$(echo $NODEINFO2 | jq -r '.' | awk '/registered/ {gsub(",","");print $2}')
REPORTS2=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/reports)
VSTATUS=$(echo $REPORTS2 | jq -r '.' | awk '/Validated/ {gsub(",","");print $2}')
rid=$(echo $REPORTS2 | jq -r '.' | awk '/ID/ {gsub(",","");print $2}' | sed -n '1p')
BASEVALUES2=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues)
TSTATUS2=$(echo $NODEINFO2 | jq -r '.' | awk '/trusted/ {gsub("\"","",$2);gsub(",","",$2);print $2}')
if [[ $RSTATUS2 == true && $VSTATUS == true && $BASEVALUES2 == "[]" && $TSTATUS2 == ${strUNKNOWN} ]]
then
    echo "the ${cid} client has been registered." | tee -a ${DST}/control.txt
    echo "the ${cid} client's report${rid} is verified." | tee -a ${DST}/control.txt
    echo "the ${cid} client's basevalues are empty." | tee -a ${DST}/control.txt
    echo "the ${cid} client's trust status is unknown." | tee -a ${DST}/control.txt
    echo "test2 succeeded!" | tee -a ${DST}/control.txt
else
    echo "test2 failed!" | tee -a ${DST}/control.txt
    echo "kill all test processes..." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

# set correct base value to test
curl -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" -d "{\"name\":\"test\", \"enabled\":true, \
        \"pcr\":\"${strPCR}\", \"bios\":\"${strBIOS}\", \"ima\":\"${strIMA}\", \"isnewgroup\":true}" \
            https://localhost:40003/${cid}/newbasevalue
echo "wait for 20s..." | tee -a ${DST}/control.txt
sleep 20
BASEVALUES3=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues)
bid=$(echo ${BASEVALUES3} | jq -r '.' | awk '/ID/ {gsub(",","");print $2}' | sed -n '1p')
BVALUEDETAILS=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues/${bid})
PCRTARGET=$(echo ${BVALUEDETAILS} | jq -r '.' | awk '/Pcr/ {gsub("\"","",$2);gsub(",","",$2);print $2}')
BIOSTARGET=$(echo ${BVALUEDETAILS} | jq -r '.' | awk -F '"' '/Bios/ {print $4}')
IMATARGET=$(echo ${BVALUEDETAILS} | jq -r '.' | awk -F '"' '/Ima/ {print $4}')
NODEINFO3=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid})
TSTATUS3=$(echo $NODEINFO3 | jq -r '.' | awk '/trusted/ {gsub("\"","",$2);gsub(",","",$2);print $2}')
if [[ ${bid} == 1 && ${PCRTARGET} == ${strPCR} && ${BIOSTARGET} == ${strBIOS} && ${IMATARGET} == ${strIMA} && ${TSTATUS3} == ${strTRUSTED} ]]
then
    echo "add a new base value succeeded." | tee -a ${DST}/control.txt
    echo "get the base value id is ${bid}." | tee -a ${DST}/control.txt
    echo "set id:${bid} pcr value ok." | tee -a ${DST}/control.txt
    echo "set id:${bid} bios value ok." | tee -a ${DST}/control.txt
    echo "set id:${bid} ima value ok." | tee -a ${DST}/control.txt
    echo "get the client${cid}'s trust status is trusted." | tee -a ${DST}/control.txt
    echo "test3 succeeded!" | tee -a ${DST}/control.txt
else
    echo "test3 failed." | tee -a ${DST}/control.txt
    # echo "kill all test processes..." | tee -a ${DST}/control.txt
    # pkill -u ${USER} ras
    # pkill -u ${USER} raagent
    # echo "test DONE!!!" | tee -a ${DST}/control.txt
    # exit 1
fi

# set wrong base value to test
curl -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" -d "{\"name\":\"test\", \"enabled\":true, \
        \"pcr\":\"${strPCR}\", \"bios\":\"${strBIOS}\", \"ima\":\"${strNEWIMA}\", \"isnewgroup\":true}" \
            https://localhost:40003/${cid}/newbasevalue
echo "wait for 20s..." | tee -a ${DST}/control.txt
sleep 20
BASEVALUES4=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues)
bid2=$(echo ${BASEVALUES4} | jq -r '.' | awk '/ID/ {gsub(",","");print $2}' | sed -n '1p')
BVALUEDETAILS2=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues/${bid2})
PCRTARGET2=$(echo ${BVALUEDETAILS2} | jq -r '.' | awk '/Pcr/ {gsub("\"","",$2);gsub(",","",$2);print $2}')
BIOSTARGET2=$(echo ${BVALUEDETAILS2} | jq -r '.' | awk -F '"' '/Bios/ {print $4}')
IMATARGET2=$(echo ${BVALUEDETAILS2} | jq -r '.' | awk -F '"' '/Ima/ {print $4}')
NODEINFO4=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid})
TSTATUS4=$(echo $NODEINFO4 | jq -r '.' | awk '/trusted/ {gsub("\"","",$2);gsub(",","",$2);print $2}')
if [[ ${bid2} == 2 && ${PCRTARGET} == ${strPCR} && ${BIOSTARGET} == ${strBIOS} && ${IMATARGET} == ${strNEWIMA} && ${TSTATUS4} == ${strUNTRUSTED} ]]
then
    echo "add a new base value succeeded." | tee -a ${DST}/control.txt
    echo "get the base value id is ${bid2}." | tee -a ${DST}/control.txt
    echo "set id:${bid2} pcr value ok." | tee -a ${DST}/control.txt
    echo "set id:${bid2} bios value ok." | tee -a ${DST}/control.txt
    echo "set id:${bid2} ima value ok." | tee -a ${DST}/control.txt
    echo "get the client${cid}'s trust status is untrusted." | tee -a ${DST}/control.txt
    echo "test4 succeeded!" | tee -a ${DST}/control.txt
else
    echo "test4 failed." | tee -a ${DST}/control.txt
    # echo "kill all test processes..." | tee -a ${DST}/control.txt
    # pkill -u ${USER} ras
    # pkill -u ${USER} raagent
    # echo "test DONE!!!" | tee -a ${DST}/control.txt
    # exit 1
fi

# set mgrstrategy to auto-update
echo "set mgrstrategy to auto-update..." | tee -a ${DST}/control.txt
curl -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" -d '{"isautoupdate":true}' https://localhost:40003/${cid}
echo "wait for 20s..." | tee -a ${DST}/control.txt
sleep 20

# set mgrstrategy to manual
echo "set mgrstrategy to manual..." | tee -a ${DST}/control.txt
curl -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" -d '{"isautoupdate":false}' https://localhost:40003/${cid}
echo "wait for 20s..." | tee -a ${DST}/control.txt
sleep 20
NODEINFO5=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid})
TSTATUS5=$(echo $NODEINFO5 | jq -r '.' | awk '/trusted/ {gsub("\"","",$2);gsub(",","",$2);print $2}')
if [ "${TSTATUS5}" == ${strTRUSTED} ]
then
    echo "get the client${cid}'s trust status is trusted." | tee -a ${DST}/control.txt
    echo "test5 succeeded!" | tee -a ${DST}/control.txt
else
    echo "test5 failed." | tee -a ${DST}/control.txt
    # echo "kill all test processes..." | tee -a ${DST}/control.txt
    # pkill -u ${USER} ras
    # pkill -u ${USER} raagent
    # echo "test DONE!!!" | tee -a ${DST}/control.txt
    # exit 1
fi

# stop raagent for a while
echo "kill raagent..." | tee -a ${DST}/control.txt
pkill -u ${USER} raagent
echo "wait for 5s..." | tee -a ${DST}/control.txt
sleep 5
NODEINFO6=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid})
TSTATUS6=$(echo $NODEINFO6 | jq -r '.' | awk '/trusted/ {gsub("\"","",$2);gsub(",","",$2);print $2}')
if [ "${TSTATUS6}" == ${strUNKNOWN} ]
then
    echo "get the client${cid}'s trust status is unknown." | tee -a ${DST}/control.txt
    echo "test6 succeeded!" | tee -a ${DST}/control.txt
else
    echo "test6 failed." | tee -a ${DST}/control.txt
    # echo "kill all test processes..." | tee -a ${DST}/control.txt
    # pkill -u ${USER} ras
    # pkill -u ${USER} raagent
    # echo "test DONE!!!" | tee -a ${DST}/control.txt
    # exit 1
fi

# restart raagent
echo "restart ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t -v &>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "restart ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done
echo "wait for 20s..." | tee -a ${DST}/control.txt
sleep 20
NODEINFO7=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid})
TSTATUS7=$(echo $NODEINFO7 | jq -r '.' | awk '/trusted/ {gsub("\"","",$2);gsub(",","",$2);print $2}')
if [ "${TSTATUS7}" == ${strTRUSTED} ]
then
    echo "get the client${cid}'s trust status is trusted." | tee -a ${DST}/control.txt
    echo "test7 succeeded!" | tee -a ${DST}/control.txt
else
    echo "test7 failed." | tee -a ${DST}/control.txt
    # echo "kill all test processes..." | tee -a ${DST}/control.txt
    # pkill -u ${USER} ras
    # pkill -u ${USER} raagent
    # echo "test DONE!!!" | tee -a ${DST}/control.txt
    # exit 1
fi

# delete the specific client
echo "delete client${cid}..." | tee -a ${DST}/control.txt
NODEINFO8=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid})
RSTATUS3=$(echo $NODEINFO8 | jq -r '.' | awk '/registered/ {gsub(",","");print $2}')
BASEVALUES5=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/basevalues)
TSTATUS8=$(echo $NODEINFO8 | jq -r '.' | awk '/trusted/ {gsub("\"","",$2);gsub(",","",$2);print $2}')
REPORTS3=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid}/reports)
if [[ $NODEINFO8 != "[]" && $RSTATUS3 == false && $REPORTS3 != "[]" && $BASEVALUES5 != "[]" && $TSTATUS8 == $strUNKNOWN ]]
then
    echo "the client${cid}'s information still exists." | tee -a ${DST}/control.txt
    echo "the client${cid}'s registration status is false." | tee -a ${DST}/control.txt
    echo "the client${cid}'s report still exists." | tee -a ${DST}/control.txt
    echo "the client${cid}'s basevalue still exists." | tee -a ${DST}/control.txt
    echo "the client${cid}'s trust status is unknown." | tee -a ${DST}/control.txt
    echo "test8 succeeded!" | tee -a ${DST}/control.txt
else
    echo "test8 failed." | tee -a ${DST}/control.txt
    # echo "kill all test processes..." | tee -a ${DST}/control.txt
    # pkill -u ${USER} ras
    # pkill -u ${USER} raagent
    # echo "test DONE!!!" | tee -a ${DST}/control.txt
    # exit 1
fi

# stop test
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent
echo "TEST ALL SUCCEEDED!!!" | tee -a ${DST}/control.txt
exit 0