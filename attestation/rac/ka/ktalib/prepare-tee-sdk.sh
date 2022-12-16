#/bin/sh
BASIC_REPO="https://gitee.com/openeuler"
SDK_REPO="itrustee_sdk"
SEC_FUNC_REPO="libboundscheck"
# this script is made for prepare tee basic sdk environment
git clone ${BASIC_REPO}/${SDK_REPO}.git
cd ./${SDK_REPO}/thirdparty/open_source
git clone ${BASIC_REPO}/${SEC_FUNC_REPO}.git
cd ./${SEC_FUNC_REPO}
make