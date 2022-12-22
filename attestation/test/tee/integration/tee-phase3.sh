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
( cd ${DST}/ras ; ./ras -T &>${DST}/ras/echo.txt ; ./ras -v &>>${DST}/ras/echo.txt ;)&

# start number of rac clients
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t -T -v &>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt
echo "wait for 20s"  | tee -a ${DST}/control.txt
sleep 20  | tee -a ${DST}/control.txt
# get cid
echo "get client id" | tee -a ${DST}/control.txt
cid=$(awk '{ if ($1 == "clientid:") { print $2 } }' ${DST}/rac-1/config.yaml)
echo ${cid} | tee -a ${DST}/control.txt
echo "modify ta verify type via restapi request"  | tee -a ${DST}/control.txt
# get restapi auth token from echo.txt
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)


# test story 3.4: set ta verify type
echo "step1: get current ta verify type via restapi request"  | tee -a ${DST}/control.txt
VTRESPONSE1=$(curl -k -X GET -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN" https://localhost:40003/config)
echo ${VTRESPONSE1} | tee -a ${DST}/control.txt
echo "step2: set new ta verify type via restapi request"  | tee -a ${DST}/control.txt
VTRESPONSE2=$(curl -X POST -k -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN" -d '{"taverifytype": 1}' https://localhost:40003/config)
echo ${VTRESPONSE2} | tee -a ${DST}/control.txt


# test story 3.5-3.6: validate ta and get ta trust status
echo "verify ta to get trust status via restapi request"  | tee -a ${DST}/control.txt
tauuid="test"
# change config
curl -X POST -k -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN" -d '{"trustduration":"40s","taverifytype": 3}' https://localhost:40003/config
#echo "step1: post a new ta basevalue(fault) via restapi request"  | tee -a ${DST}/control.txt
#TSRESPONSE1=$(curl -X POST -H "Content-Type: application/json" -H "Authorization: $AUTHTOKEN" -k https://localhost:40003/${cid}/ta/${tauuid}/newtabasevalue -d '{"name":"testname", "enabled":true, "valueinfo":"test info"}')
#echo ${TSRESPONSE1} | tee -a ${DST}/control.txt
#echo "step2: verify ta and get ta turst status"  | tee -a ${DST}/control.txt
#TSRESPONSE2=$(curl -k -X GET -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN" https://localhost:40003/${cid}/ta/${tauuid}/tareports)
#echo ${TSRESPONSE2} | tee -a ${DST}/control.txt
echo "wait for 20s"  | tee -a ${DST}/control.txt
sleep 20  | tee -a ${DST}/control.txt
#echo "step3: post a new ta basevalue(correct) via restapi request"  | tee -a ${DST}/control.txt
#TSRESPONSE3=$(curl -X POST -H "Content-Type: application/json" -H "Authorization: $AUTHTOKEN" -k https://localhost:40003/${cid}/ta/${tauuid}/newtabasevalue -d '{"name":"testname", "enabled":true, "valueinfo":"test info"}')
#echo ${TSRESPONSE3} | tee -a ${DST}/control.txt
#echo "step4: verify ta and get ta turst status"  | tee -a ${DST}/control.txt
TSRESPONSE4=$(curl -k -X GET -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN" https://localhost:40003/${cid}/ta/${tauuid}/tareports)
echo ${TSRESPONSE4} | tee -a ${DST}/control.txt


### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent

echo "test DONE!!!" | tee -a ${DST}/control.txt

### analyse the testing data
TAVerifyType1=$(echo $VTRESPONSE1 | jq -r '.' | grep -A 0 "taverifytype" |  awk -F ':' '{print $2}')
TAVerifyType2=$(echo $VTRESPONSE2 | jq -r '.' | grep -A 0 "taverifytype" |  awk -F ':' '{print $2}')
#STATUS1=$(echo $TSRESPONSE2 | jq -r '.' | grep -A 0 "Trusted" |  awk -F ':' '{print $2}')
VALIDATED=$(echo $TSRESPONSE4 | jq -r '.' | grep -A 0 "Validated" |  awk -F ':' '{print $2}')
STATUS2=$(echo $TSRESPONSE4 | jq -r '.' | grep -A 0 "Trusted" |  awk -F ':' '{print $2}')

### generate the test report
echo "ClientID:${cid}"  | tee -a ${DST}/control.txt
echo "TAVerifyType1:${TAVerifyType1}  TAVerifyType2:${TAVerifyType2}"  | tee -a ${DST}/control.txt
echo "Validated:${VALIDATED}  Status2:${STATUS2}"  | tee -a ${DST}/control.txt
if [ ${TAVerifyType1} == 3 ] && [ ${TAVerifyType2} == 1 ] && [ ${VALIDATED} == "true," ] && [ ${STATUS2} == "true," ]
then
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
