#/bin/sh
BASIC_REPO="https://gitee.com/openeuler"
SDK_REPO="itrustee_sdk"
# this script is made for prepare tee basic sdk environment
git clone ${BASIC_REPO}/${SDK_REPO}.git
cd ./${SDK_REPO}/thirdparty/open_source
git clone ${BASIC_REPO}/libboundscheck.git
cd ./libboundscheck
make