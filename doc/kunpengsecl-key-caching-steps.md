# kunpengsecl key caching steps

This is just a quick recording about how to run the whole key caching management feature

## steps to prepare the test env at the very beginning

download itrustee_sdk, itrustee_tzdriver, itrustee_client under /root/
duplicate 2 copy from itrustee_sdk as itrustee_sdk_for_kta and itrustee_sdk_for_demota
prepare developer license under the two folders.
clone kunpengsecl under /root/
mkdir -p /root/vendor/bin /root/data

## make & deploy ras/kcms, raagent/ka, qcaserver

cd /root/kunpengsecl;
make sure ta attestation being skipped in function /root/kunpengsecl/attestation/ras/kcms/kcmstools/kcmstools.go:GetKTATrusted()
make clean; make build; cp -rf /root/kunpengsecl/attestation/rac/pkg/raagent /usr/bin/raagent

## make & deploy demo ca

cp -rf /root/kunpengsecl/attestation/tee/demo/demo_ca /root/itrustee_sdk_for_demota/test/CA/
create makefile for demo_ca
cd /root/itrustee_sdk_for_demota/test/CA/demo_ca; make; cp -f demo_ca /root/vendor/bin
 
## make & deploy demo ta

cp -rf /root/kunpengsecl/attestation/tee/demo/demo_ta /root/itrustee_sdk_for_demota/test/TA/
cp -rf /root/kunpengsecl/attestation/tee/kcml /root/itrustee_sdk_for_demota/test/TA/demo_ta/
create makefile for demo_ta
cd /root/itrustee_sdk_for_demota/test/TA/demo_ta; make; cp -f /root/itrustee_sdk_for_demota/test/TA/demo_ta/bbb2d138-ee21-43af-8796-40c20d7b45fa.sec /root/data

## make & deploy kta

cp -rf /root/kunpengsecl/attestation/tee/kta /root/itrustee_sdk_for_kta/test/TA/
create makefile for kta
cd /root/itrustee_sdk_for_kta/test/TA/kta; make; cp -f /root/itrustee_sdk_for_kta/test/TA/kta/435dcafa-0029-4d53-97e8-a7a13a80c82e.sec /root/data

## prepare key & cert for kcm & kta

cd /root/kunpengsecl/attestation/quick-scripts/; bash clear-database.sh; bash prepare-kcm-env.sh

## launch qcaserver in console 0

cd /root/kunpengsecl/attestation/tee/demo/qca_demo/cmd/; /root/kunpengsecl/attestation/tee/demo/pkg/qcaserver

## launch ras,  kcms in console 1

cd /root/kunpengsecl/attestation/ras/cmd/; /root/kunpengsecl/attestation/ras/pkg/ras -T; /root/kunpengsecl/attestation/ras/pkg/ras

## launch raagent & kta in console 2

cd /root/kunpengsecl/attestation/rac/cmd/raagent; git checkout config.yaml; /usr/bin/raagent -t -v -k -S; /usr/bin/raagent -t -v -k

## launch demo_ca & demo_ta in console 3

cd /root/kunpengsecl/attestation/tee/demo/demo_ca; /root/vendor/bin/demo_ca

## some quick scripts

### 1. sync code from tree to build folders

cp -rf /root/kunpengsecl/attestation/tee/demo/demo_ca /root/itrustee_sdk_for_demota/test/CA/
cp -rf /root/kunpengsecl/attestation/tee/demo/demo_ta /root/itrustee_sdk_for_demota/test/TA/
cp -rf /root/kunpengsecl/attestation/tee/kcml /root/itrustee_sdk_for_demota/test/TA/demo_ta/
cp -rf /root/kunpengsecl/attestation/tee/kta /root/itrustee_sdk_for_kta/test/TA/

### 2. sync code from build folders to tree

cp -f /root/itrustee_sdk_for_demota/test/CA/demo_ca/\* /root/kunpengsecl/attestation/tee/demo/demo_ca/ 
cp -f /root/itrustee_sdk_for_demota/test/TA/demo_ta/\* /root/kunpengsecl/attestation/tee/demo/demo_ta/ 
cp -f /root/itrustee_sdk_for_demota/test/TA/demo_ta/kcml/\* /root/kunpengsecl/attestation/tee/kcml/ 
cp -f /root/itrustee_sdk_for_kta/test/TA/kta/\* /root/kunpengsecl/attestation/tee/kta/

### 3. batch build & deploy

cd /root/kunpengsecl; make clean; make build; cp -f /root/kunpengsecl/attestation/rac/pkg/raagent /usr/bin/raagent
cd /root/itrustee_sdk_for_demota/test/CA/demo_ca; make; cp -f demo_ca /root/vendor/bin
cd /root/itrustee_sdk_for_demota/test/TA/demo_ta; make; cp -f /root/itrustee_sdk_for_demota/test/TA/demo_ta/bbb2d138-ee21-43af-8796-40c20d7b45fa.sec /root/data
cd /root/itrustee_sdk_for_kta/test/TA/kta; make; cp -f /root/itrustee_sdk_for_kta/test/TA/kta/435dcafa-0029-4d53-97e8-a7a13a80c82e.sec /root/data

### 4. launch test

cd /root/kunpengsecl/attestation/quick-scripts/; bash clear-database.sh; bash prepare-kcm-env.sh
cd /root/kunpengsecl/attestation/ras/cmd/; /root/kunpengsecl/attestation/ras/pkg/ras -T; /root/kunpengsecl/attestation/ras/pkg/ras -v
cd /root/kunpengsecl/attestation/tee/demo/qca_demo/cmd/; /root/kunpengsecl/attestation/tee/demo/pkg/qcaserver
cd /root/kunpengsecl/attestation/rac/cmd/raagent; git checkout config.yaml; rm *.crt; /usr/bin/raagent -t -v -k -S; /usr/bin/raagent -t -v -k
cd /root/kunpengsecl/attestation/tee/demo/demo_ca; /root/vendor/bin/demo_ca
