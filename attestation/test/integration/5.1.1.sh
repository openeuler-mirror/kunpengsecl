#!/bin/bash
# this script only support openeuler or other using rpm package system!!!
# Please run this script under the root folder of kunpengsecl project otherwise it will be wrong!
# gnome-terminal is required.
#set -eux
### prepare the test environment
git clone https://gitee.com/openeuler/kunpengsecl.git
cd kunpengsecl/
make
PROJROOT=.
RPMPATH=${PROJROOT}/rpmbuild/RPMS/x86_64
RASPATH=${PROJROOT}/attestation/ras/cmd/ras
RAHUBPATH=${PROJROOT}/attestation/rac/cmd/rahub
RACPATH=${PROJROOT}/attestation/rac/cmd/raagent
VERSION=1.0.0
RELEASE=3
# include common part
. ${PROJROOT}/attestation/test/integration/common.sh
echo "start test..." | tee -a ${DST}/control.txt
sudo rpm -e kunpengsecl-ras-${VERSION}-${RELEASE}.x86_64
sudo rpm -e kunpengsecl-rahub-${VERSION}-${RELEASE}.x86_64
sudo rpm -e kunpengsecl-rac-${VERSION}-${RELEASE}.x86_64

### make the rpm package
echo "start packaging..." | tee -a ${DST}/control.txt
make rpm
echo "finish packaging..." | tee -a ${DST}/control.txt

### install ras rahub raagent into system
echo "start installing..." | tee -a ${DST}/control.txt
sudo rpm -ivh ${RPMPATH}/kunpengsecl-ras-${VERSION}-${RELEASE}.x86_64.rpm
sudo rpm -ivh ${RPMPATH}/kunpengsecl-rahub-${VERSION}-${RELEASE}.x86_64.rpm
sudo rpm -ivh ${RPMPATH}/kunpengsecl-rac-${VERSION}-${RELEASE}.x86_64.rpm
echo "finish installing..." | tee -a ${DST}/control.txt

### run ras
echo "start ras..." | tee -a ${DST}/control.txt
pushd $(pwd)
cd ${RASPATH}
gnome-terminal --title="ras" -e ras
popd
echo "wait for 5s"
sleep 5

### run rahub
echo "start rahub..." | tee -a ${DST}/control.txt
pushd $(pwd)
cd ${RAHUBPATH}
gnome-terminal --title="rahub" -e rahub
popd
echo "wait for 5s"
sleep 5

### run rac
echo "start raagent..." | tee -a ${DST}/control.txt
pushd $(pwd)
cd ${RACPATH}
gnome-terminal --title="rac" -e "raagent -t"
popd
echo "wait for 10s"
sleep 10
echo "kill all processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} raagent
pkill -u ${USER} rahub
pkill -u ${USER} ras
echo "test done!!!" | tee -a ${DST}/control.txt
