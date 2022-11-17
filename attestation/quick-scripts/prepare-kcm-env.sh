#/bin/sh
### This script is used to prepare the certificate chain needed for key-cache program execution.

KCMSPATH=../ras/kcms/cert
KAPATH=../rac/ka/cert
CAVAR=./var
ca_subj="/C=CN/ST=Shanghai/L=Shanghai/O=Huawei/CN=ca"
kta_subj="/C=CN/ST=Shanghai/L=Shanghai/O=Huawei/CN=kta"
kcm_subj="/C=CN/ST=Shanghai/L=Shanghai/O=Huawei/CN=kcm"
days=356 # Validity of certificate

mkdir -p -m 755 ${CAVAR}
mkdir -p -m 755 ${KAPATH}
mkdir -p -m 755 ${KCMSPATH}

### generate root key and certificate
cd ${CAVAR}
mkdir -p demoCA/newcerts
touch demoCA/index.txt
touch demoCA/serial
touch demoCA/private
echo 01 > demoCA/serial
openssl req -new -x509 -days $days -keyout ca.key -out ca.crt -passout pass:123456 -subj "${ca_subj}"
openssl rsa -in ca.key -out ca.key -passin pass:123456

#kta
#Generate the kta private key (the encryption method is des3, and the password is 123456 2048 bytes)
openssl genrsa -des3 -passout pass:123456 -out kta.key 2048
openssl rsa -in kta.key -out kta.key -passin pass:123456
#Generate certificate request file
openssl req -new -key kta.key -out kta.csr -subj "${kta_subj}"
#CA issuing certificate
openssl ca -in kta.csr -out kta.crt -cert ca.crt -keyfile ca.key -days $days -policy policy_anything

#kcm
openssl genrsa -des3 -passout pass:123456 -out kcm.key 2048
openssl rsa -in kcm.key -out kcm.key -passin pass:123456
openssl req -new -key kcm.key -out kcm.csr -subj "${kcm_subj}"
openssl ca -in kcm.csr -out kcm.crt -cert ca.crt -keyfile ca.key -days $days -policy policy_anything

cd ..

cp $CAVAR/ca.crt $KAPATH
cp $CAVAR/ca.crt $KCMSPATH
cp $CAVAR/kcm.crt $KCMSPATH
cp $CAVAR/kcm.key $KCMSPATH
cp $CAVAR/kta.crt $KAPATH
cp $CAVAR/kta.key $KAPATH

rm -rf $CAVAR