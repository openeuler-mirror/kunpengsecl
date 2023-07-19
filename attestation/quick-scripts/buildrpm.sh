#!/bin/bash
# define some constants
Name=kunpengsecl
Version=v2.0.2

# install the rpm tools.
#yum -y install rpm-build rpmdevtools rpm-devel

# Notice: run this script at kunpengsecl root directory,
# otherwise, this %_topdir will be wrong!!!
echo '%_topdir %(echo $PWD)/../rpmbuild' > ~/.rpmmacros
# prepare the rpm working directory.
mkdir -p ../rpmbuild/{BUILD,BUILDROOT,RPMS,SRPMS,SOURCES}

# clean useless directories and files.
make clean
rm -rf ./attestation/{vendor,go.sum}

# build source tar ball.
tar -czf ../rpmbuild/SOURCES/$Name-$Version.tar.gz \
            attestation doc rpmbuild \
            LICENSE Makefile README.md README.en.md
# build vendor tar ball.
make vendor
tar -czf ../rpmbuild/SOURCES/vendor.tar.gz \
            attestation/vendor attestation/go.sum

go env -w GO111MODULE="on"
rpmbuild -ba ./rpmbuild/SPECS/kunpengsecl.spec
