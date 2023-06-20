#!/bin/bash

# Notice: run this script at kunpengsecl root directory
topdir=`pwd`
VERSION="2.0.1"

##########################
# create rac.deb
##########################
RAC_CONTROL="\
Package: rac
Version: ${VERSION}
License: MulanPSL-2.0
Architecture: amd64
Maintainer: Wucaijun
Section: utils
Priority: optional
Recommends: openssl, libssl1.1, libssl-dev, libcjson1, libcjson-dev
Description: This is the rac deb package, which is used to install the client of the program.

"

rm -rf ./debbuild
mkdir -p ./debbuild/{DEBIAN,etc/attestation/rac,etc/attestation/default_test,usr/bin,usr/lib64,usr/share/attestation/rac,usr/share/doc/attestation/rac}
echo -e "${RAC_CONTROL}" > ./debbuild/DEBIAN/control
cp ./attestation/rac/pkg/raagent ./debbuild/usr/bin
cp ./attestation/rac/cmd/raagent/config.yaml ./debbuild/etc/attestation/rac
cp ./attestation/rac/cmd/raagent/ascii_runtime_measurements* ./debbuild/etc/attestation/default_test
cp ./attestation/rac/cmd/raagent/binary_bios_measurements* ./debbuild/etc/attestation/default_test
cp ./attestation/quick-scripts/integritytools/* ./debbuild/usr/share/attestation/rac
cp ./attestation/quick-scripts/prepare-racconf-env.sh ./debbuild/usr/share/attestation/rac
cp ./README* ./debbuild/usr/share/doc/attestation/rac
cp ./LICENSE ./debbuild/usr/share/doc/attestation/rac
echo "build deb..."
dpkg-deb -b debbuild
echo "rename deb..."
dpkg-name debbuild.deb


##########################
# create ras.deb
##########################
RAS_CONTROL="\
Package: ras
Version: ${VERSION}
License: MulanPSL-2.0
Architecture: amd64
Maintainer: Wucaijun
Section: utils
Priority: optional
Recommends: openssl, libssl1.1, libssl-dev, libcjson1, libcjson-dev
Description: This is the ras deb package, which is used to install the server of the program.

"

rm -rf ./debbuild
mkdir -p ./debbuild/{DEBIAN,etc/attestation/ras,etc/attestation/default_test,usr/bin,usr/lib64,usr/share/attestation/ras,usr/share/doc/attestation/ras}
echo -e "${RAS_CONTROL}" > ./debbuild/DEBIAN/control
cp ./attestation/ras/pkg/ras ./debbuild/usr/bin
cp ./attestation/ras/cmd/config.yaml ./debbuild/etc/attestation/ras
cp ./attestation/quick-scripts/prepare-database-env.sh ./debbuild/usr/share/attestation/ras
cp ./attestation/quick-scripts/clear-database.sh ./debbuild/usr/share/attestation/ras
cp ./attestation/quick-scripts/createTable.sql ./debbuild/usr/share/attestation/ras
cp ./attestation/quick-scripts/clearTable.sql ./debbuild/usr/share/attestation/ras
cp ./attestation/quick-scripts/dropTable.sql ./debbuild/usr/share/attestation/ras
cp ./attestation/quick-scripts/prepare-rasconf-env.sh ./debbuild/usr/share/attestation/ras
cp ./README* ./debbuild/usr/share/doc/attestation/ras
cp ./LICENSE ./debbuild/usr/share/doc/attestation/ras
echo "build deb..."
dpkg-deb -b debbuild
echo "rename deb..."
dpkg-name debbuild.deb


##########################
# create rahub.deb
##########################
RAHUB_CONTROL="\
Package: rahub
Version: ${VERSION}
License: MulanPSL-2.0
Architecture: amd64
Maintainer: Wucaijun
Section: utils
Priority: optional
Recommends: openssl, libssl1.1, libssl-dev, libcjson1, libcjson-dev
Description: This is the rahub deb package, which is used to cascade clients.

"

rm -rf ./debbuild
mkdir -p ./debbuild/{DEBIAN,etc/attestation/rahub,etc/attestation/default_test,usr/bin,usr/lib64,usr/share/attestation/rahub,usr/share/doc/attestation/rahub}
echo -e "${RAHUB_CONTROL}" > ./debbuild/DEBIAN/control
cp ./attestation/rac/pkg/rahub ./debbuild/usr/bin
cp ./attestation/rac/cmd/rahub/config.yaml ./debbuild/etc/attestation/rahub
cp ./attestation/quick-scripts/prepare-hubconf-env.sh ./debbuild/usr/share/attestation/rahub
cp ./README* ./debbuild/usr/share/doc/attestation/rahub
cp ./LICENSE ./debbuild/usr/share/doc/attestation/rahub
echo "build deb..."
dpkg-deb -b debbuild
echo "rename deb..."
dpkg-name debbuild.deb

