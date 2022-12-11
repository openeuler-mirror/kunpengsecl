#/bin/sh

# this script must be executed after the ras runs
# this script can be excuted in any directories
FILE="bbb2d138-ee21-43af-8796-40c20d7b45fa.sec"
KTA_PATH="/root/itrustee_sdk/test/TA/kta"
RAC_PKG_PATH="/root/kunpengsecl/attestation/rac/pkg"

cd /root/itrustee_tzdriver
insmod tzdriver.ko
/usr/bin/teecd & /usr/bin/tlogcat -f &
cd ${KTA_PATH}
make
sleep 5
rm -f /root/data/${FILE}
cp ${KTA_PATH}/${FILE} /root/data/${FILE}
cd ${RAC_PKG_PATH}
${RAC_PKG_PATH}/raagent -t -v