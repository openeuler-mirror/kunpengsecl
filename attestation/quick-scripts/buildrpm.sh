#!/bin/bash
# define some constants
Name=kunpengsecl
Version=v1.1.0

# install the rpm tools.
#yum -y install rpm-build rpmdevtools rpm-devel

# Notice: run this script at kunpengsecl root directory,
# otherwise, this %_topdir will be wrong!!!
echo '%_topdir %(echo $PWD)/rpmbuild' > ~/.rpmmacros
# prepare the rpm working directory.
mkdir -p ./rpmbuild/{BUILD,BUILDROOT,RPMS,SRPMS,SOURCES}

# clean useless directories and files.
make clean
rm -rf ./attestation/{vendor,go.sum}
make vendor

# build source tar ball.
tar -czf ./rpmbuild/SOURCES/$Name-$Version.tar.gz \
            attestation doc \
            LICENSE Makefile README.md README.en.md

go env -w GO111MODULE="on"
rpmbuild -ba ./rpmbuild/SPECS/kunpengsecl.spec