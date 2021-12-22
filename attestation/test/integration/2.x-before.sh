#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project and run as super-user.
# set -eux
PROJROOT=.
# include common part
. ${PROJROOT}/attestation/test/integration/common.sh

###use integritytools to enable container-measurment
cd ${PROJROOT}/attestation/quick-scripts/integritytools
echo "enable host measurement" | tee -a ${DST}/control.txt
echo n | sh hostintegritytool.sh | tee -a ${DST}/control.txt
echo "enable container measurement" | tee -a ${DST}/control.txt
echo y | sh containerintegritytool.sh | tee -a ${DST}/control.txt