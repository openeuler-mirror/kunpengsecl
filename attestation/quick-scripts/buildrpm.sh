#!/bin/bash

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
rm -rf ./integration/{vendor,go.sum}

# build source tar ball.
tar -czf ./rpmbuild/SOURCES/kunpengsecl-1.1.tar.gz \
            attestation doc integration \
            LICENSE Makefile README.md README.en.md

go env -w GO111MODULE="on"
rpmbuild -ba ./rpmbuild/SPECS/kunpengsecl.spec
