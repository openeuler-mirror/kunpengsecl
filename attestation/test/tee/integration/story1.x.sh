# this scripts should be run under the root folder of kunpengsecl project
PROJROOT=.

FILENAME=`basename $0`
CASENAME=${FILENAME%.*}

TESTDIR_PREFIX=${TESTDIR_PREFIX:-kunpengsecl-tee-test}
DST=$(mktemp -t -d ${TESTDIR_PREFIX}-XXXXXX)

PKGPATH=${PROJROOT}/attestation/tee/demo/pkg
CMDQCASERVER=${PROJROOT}/attestation/tee/demo/qca_demo/cmd
CMDATTESTER=${PROJROOT}/attestation/tee/demo/attester_demo/cmd

QCASERVER=${PKGPATH}/qcaserver
QCACONF=${CMDQCASERVER}/config.yaml
ATTESTER=${PKGPATH}/attester
ATTESTERCONF=${CMDATTESTER}/config.yaml
BASEVALUE=${CMDATTESTER}/basevalue.txt

# run number of attester clients to test
NUM=${NUM:-4}

# all the test result. (0 = test failed; 1 = test successful)
RESULT1=0
RESULT2=0
RESULT3=0
RESULT4=0
RESULT5=0

# judgment string
AKGENERATION="Generate RSA AK and AK Cert succeeded!"
RPGENERATION="Generate TA report succeeded!"
REPORTGET="Get TA report succeeded!"
MEASUREMENTPOLICY="TEE Measurement: 1"
TAVERIFICATION="tee verify succeeded!"

echo "=========="
echo "start ${CASENAME} at: $(date)" | tee -a ${DST}/control.txt
echo "prepare the test environments..." | tee -a ${DST}/control.txt

# prepare qcaserver
mkdir -p ${DST}/qca
cp ${QCASERVER} ${DST}/qca
cp ${QCACONF} ${DST}/qca

# prepare attester
mkdir -p ${DST}/attester
cp ${ATTESTER} ${DST}/attester
cp ${ATTESTERCONF} ${DST}/attester
cp ${BASEVALUE} ${DST}/attester
for i in `seq ${NUM}`
do
    ATTESTERDIR=${DST}/attester-${i}
    mkdir -p ${ATTESTERDIR}
    ln -s ${DST}/attester/config.yaml ${ATTESTERDIR}
    ln -s ${DST}/attester/basevalue.txt ${ATTESTERDIR}
done

########## ------story test------ ##########
### story1.1 TEE AK GENERATION TEST
# start launching qcaserver for testing
echo "start qcaserver and generate AK/AKCert..." | tee -a ${DST}/control.txt
( cd ${DST}/qca ; ./qcaserver > ${DST}/qca/echo.out 2>&1 ; )&
echo "end qcaserver..." | tee -a ${DST}/control.txt
sleep 3
pkill -u ${USER} qcaserver
if [ `grep -c "${AKGENERATION}" ${DST}/qca/echo.out` -ne '0' ]; then
    echo "QTA generate AK/AKCert succeeded!" | tee -a ${DST}/control.txt ; RESULT1=1
else
    echo "QTA generate AK/AKCert failed!" | tee -a ${DST}/control.txt ; RESULT1=0
fi

### story1.2 TA REPORT GENERATION TEST
# start launching qcaserver for testing
echo "start qcaserver and generate TA report..." | tee -a ${DST}/control.txt
( cd ${DST}/qca ; ./qcaserver > ${DST}/qca/echo.out 2>&1 ; )&
# start launching attester for testing
echo "start attester..." | tee -a ${DST}/control.txt
( cd ${DST}/attester-1 ; ${DST}/attester/attester -T > ${DST}/attester-1/echo.out 2>&1 ; )&
echo "end qcaserver..." | tee -a ${DST}/control.txt
sleep 3
pkill -u ${USER} qcaserver
if [ `grep -c "${RPGENERATION}" ${DST}/qca/echo.out` -ne '0' ]; then
    echo "QTA generate Report succeeded!" | tee -a ${DST}/control.txt ; RESULT2=1
else
    echo "QTA generate Report failed!" | tee -a ${DST}/control.txt ; RESULT2=0
fi

### story1.3 TA REPORT GET TEST
# start launching qcaserver for testing
echo "start qcaserver..." | tee -a ${DST}/control.txt
( cd ${DST}/qca ; ./qcaserver > ${DST}/qca/echo.out 2>&1 ; )&
echo "start attester and get TA report..." | tee -a ${DST}/control.txt
( cd ${DST}/attester-2 ; ${DST}/attester/attester -T > ${DST}/attester-2/echo.out 2>&1 ; )&
echo "end qcaserver..." | tee -a ${DST}/control.txt
sleep 3
pkill -u ${USER} qcaserver
if [ `grep -c "${REPORTGET}" ${DST}/attester-2/echo.out` -ne '0' ]; then
    echo "ATTESTER get Report succeeded!" | tee -a ${DST}/control.txt ; RESULT3=1
else
    echo "ATTESTER get Report failed!" | tee -a ${DST}/control.txt ; RESULT3=0
fi

### story1.4 TA VERIFY POLICY SET TEST
# start launching qcaserver for testing
echo "start qcaserver..." | tee -a ${DST}/control.txt
( cd ${DST}/qca ; ./qcaserver > ${DST}/qca/echo.out 2>&1 ; )&
echo "start attester and set the measurement policy..." | tee -a ${DST}/control.txt
( cd ${DST}/attester-3 ; ${DST}/attester/attester -T -M 1 > ${DST}/attester-3/echo.out 2>&1 ; )&
echo "end qcaserver..." | tee -a ${DST}/control.txt
sleep 3
pkill -u ${USER} qcaserver
if [ `grep -c "${MEASUREMENTPOLICY}" ${DST}/attester-3/echo.out` -ne '0' ]; then
    echo "ATTESTER set the measurement policy succeeded!" | tee -a ${DST}/control.txt ; RESULT4=1
else
    echo "ATTESTER set the measurement policy failed!" | tee -a ${DST}/control.txt ; RESULT4=0
fi

### story1.5 TA INTEGRITY VERIFICATION TEST
# start launching qcaserver for testing
echo "start qcaserver..." | tee -a ${DST}/control.txt
( cd ${DST}/qca ; ./qcaserver > ${DST}/qca/echo.out 2>&1 ; )&
echo "start attester and verify TA..." | tee -a ${DST}/control.txt
( cd ${DST}/attester-4 ; ${DST}/attester/attester -T > ${DST}/attester-4/echo.out 2>&1 ; )&
echo "end qcaserver..." | tee -a ${DST}/control.txt
sleep 3
pkill -u ${USER} qcaserver
if [ `grep -c "${TAVERIFICATION}" ${DST}/attester-4/echo.out` -ne '0' ]; then
    echo "ATTESTER verify TA succeeded!" | tee -a ${DST}/control.txt ; RESULT5=1
else
    echo "ATTESTER verify TA failed!" | tee -a ${DST}/control.txt ; RESULT5=0
fi

### final test result
if [ ${RESULT1} -eq 1 ] && [ ${RESULT2} -eq 1 ] && [ ${RESULT3} -eq 1 ] && [ ${RESULT4} -eq 1 ] && [ ${RESULT5} -eq 1 ]; then
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else 
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi