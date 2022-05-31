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
NUM=${NUM:-11}

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

# start launching qcaserver for testing
echo "start qcaserver..." | tee -a ${DST}/control.txt
( cd ${DST}/qca ; ./qcaserver &>${DST}/qca/echo.txt ; )&

# start number of attester clients
echo "start ${NUM} attester clients..." | tee -a ${DST}/control.txt
### start with none cmd parameters except -T which ensure successful verification of nonce
( cd ${DST}/attester-1 ; ${DST}/attester/attester -T &>${DST}/attester-1/echo.txt ; )&
echo "start attester-1 at $(date)..." | tee -a ${DST}/control.txt
echo "wait for 5s"
sleep 5
### start with showing app version and then exit(normal)
( cd ${DST}/attester-2 ; ${DST}/attester/attester -V &>${DST}/attester-2/echo.txt ; )&
echo "start attester-2 at $(date)..." | tee -a ${DST}/control.txt
echo "wait for 5s"
sleep 5
### start with showing app version and then exit(abnormal)
( cd ${DST}/attester-3 ; ${DST}/attester/attester -V f46s6f1f16 &>${DST}/attester-3/echo.txt ; )&
echo "start attester-3 at $(date)..." | tee -a ${DST}/control.txt
echo "wait for 5s"
sleep 5
### start with specifying the IP address of the port to be connected(normal)
( cd ${DST}/attester-4 ; ${DST}/attester/attester -T -S "127.0.0.1:40007" &>${DST}/attester-4/echo.txt ; )&
echo "start attester-4 at $(date)..." | tee -a ${DST}/control.txt
echo "wait for 5s"
sleep 5
### start with specifying the IP address of the port to be connected(abnormal)
( cd ${DST}/attester-5 ; ${DST}/attester/attester -T -S "127.0.0.1:40008" &>${DST}/attester-5/echo.txt ; )&
echo "start attester-5 at $(date)..." | tee -a ${DST}/control.txt
echo "wait for 5s"
sleep 5
### start with setting the file path of basevalue to be read(normal)
( cd ${DST}/attester-6 ; ${DST}/attester/attester -T -B "./basevalue.txt" &>${DST}/attester-6/echo.txt ; )&
echo "start attester-6 at $(date)..." | tee -a ${DST}/control.txt
echo "wait for 5s"
sleep 5
### start with setting the file path of basevalue to be read(abnormal)
( cd ${DST}/attester-7 ; ${DST}/attester/attester -T -B "../basevalue.txt" &>${DST}/attester-7/echo.txt ; )&
echo "start attester-7 at $(date)..." | tee -a ${DST}/control.txt
echo "wait for 5s"
sleep 5
### start with setting a measurement policy to be used(normal)
( cd ${DST}/attester-8 ; ${DST}/attester/attester -T -M 1 &>${DST}/attester-8/echo.txt ; )&
echo "start attester-8 at $(date)..." | tee -a ${DST}/control.txt
echo "wait for 5s"
sleep 5
### start with setting a measurement policy to be used(abnormal)
( cd ${DST}/attester-9 ; ${DST}/attester/attester -T -M 1as5d2sd1 &>${DST}/attester-9/echo.txt ; )&
echo "start attester-9 at $(date)..." | tee -a ${DST}/control.txt
echo "wait for 5s"
sleep 5
### start with specifying the QTA to be verifier(normal)
( cd ${DST}/attester-10 ; ${DST}/attester/attester -T -U "C29D01B0-CD13-405A-99F9-06343DFBE691" &>${DST}/attester-10/echo.txt ; )&
echo "start attester-10 at $(date)..." | tee -a ${DST}/control.txt
echo "wait for 5s"
sleep 5
### start with specifying the QTA to be verifier(abnormal)
( cd ${DST}/attester-11 ; ${DST}/attester/attester -T -U "afg51F1" &>${DST}/attester-11/echo.txt ; )&
echo "start attester-11 at $(date)..." | tee -a ${DST}/control.txt
echo "wait for 5s"
sleep 5

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} qcaserver
pkill -u ${USER} attester
echo "test DONE!!!" | tee -a ${DST}/control.txt
