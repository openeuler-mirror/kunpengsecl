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
NUM=${NUM:-10}

# judgment string
CONNECTION="Server: fail to serve"
TEEVERIFY="tee verify succeeded!"

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

# start test
echo "start qcaserver..." | tee -a ${DST}/control.txt
( cd ${DST}/qca ; ./qcaserver > ${DST}/qca/echo.out 2>&1 ; )&

for i in `seq ${NUM}`
do
    echo "start attester-${i}..." | tee -a ${DST}/control.txt
    (cd ${DST}/attester-${i} ; ${DST}/attester/attester -T > ${DST}/attester-${i}/echo.out 2>&1 ; )&
done

echo "wait for 60s" | tee -a ${DST}/control.txt
sleep 60

echo "kill all processes" | tee -a ${DST}/control.txt
pkill -u ${USER} qcaserver
pkill -u ${USER} attester

if [[ `grep -c "${CONNECTION}" ${DST}/qca/echo.out` -eq '0' ]] && [[ `grep -c "${TEEVERIFY}" ${DST}/attester-${NUM}/echo.out` -ne '0' ]]; then
    echo "test succeeded!" | tee -a ${DST}/control.txt ;
else
    echo "test failed!" | tee -a ${DST}/control.txt ;
fi