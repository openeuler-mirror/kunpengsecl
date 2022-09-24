#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
# run number of rac clients to test
NUM=1
# include common part
. ${PROJROOT}/attestation/test/integration/common.sh

# above are common preparation steps, below are specific preparation step, scope includs:
# configure files, input files, environment variables, cmdline paramenters, flow control paramenters, etc.
### Start Preparation
echo "start test preparation..." | tee -a ${DST}/control.txt
pushd $(pwd)
cd ${PROJROOT}/attestation/quick-scripts
echo "clean database" | tee -a ${DST}/control.txt
sh clear-database.sh | tee -a ${DST}/control.txt
popd
### Add the self cert and key to test pca'function
echo "-----BEGIN CERTIFICATE-----
MIIDOTCCAiGgAwIBAgIBATANBgkqhkiG9w0BAQsFADA0MQ4wDAYDVQQGEwVDaGlu
YTEQMA4GA1UEChMHQ29tcGFueTEQMA4GA1UEAxMHUm9vdCBDQTAeFw0yMTEyMjMw
NzU4MDNaFw0zMTEyMjMwNzU4MTNaMDQxDjAMBgNVBAYTBUNoaW5hMRAwDgYDVQQK
EwdDb21wYW55MRAwDgYDVQQDEwdSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAutPJP8BFknDSOFj9c6T/XS6YYRgnK7236f5pwEFICMJJNS6r
PQZGxfdf9VLBBPEITknplSOP7vpnojqPWRWCF7pz2T/GMRFl2ahcIiR4IlUo6kcs
HkfGm85vXvg0sgJZDLgkCtZCfHbzBTFv1Z8td80AkkLVodC+OxZ59Ip8Us3f0zx4
WTZzbnfatI3cI0pqsazbTV2gzYJiAVf6Pd87JfesfELNN71lU0W+Jz1mfPb/Gt2P
fHgGfIh5mienHtRFrLtX2oUl9d9oTMAh55h0tjAqdHB8Cbx3ZOFIdm91ROTm5AJM
Ejgrbj5H4skMdoILxE7L2i64OnF5cbmuEw2juQIDAQABo1YwVDAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0lBAgwBgYEVR0lADASBgNVHRMBAf8ECDAGAQH/AgECMB0GA1Ud
DgQWBBTyiiNa30Oj5RQVvkR6R40jD18u/DANBgkqhkiG9w0BAQsFAAOCAQEAGv3h
eDnIizbG1bh0JZvXJreAcEMW9yv/7XVj/n8KxHF+XzKQc0Y+VCIVQc3qQ4ActNRY
Ta92ixaDe80Xye+B3jyiDh0V2HVZIPaZkGzWbXa3wlQUSlKas+3rhFBzin17U1FC
R+KbU/2KIdfloEwBlXtU8j2UVw0plEiWWuAWBiNhQphAELrY4Vd6aSALUyShhz6f
fOOHqkldYhDULbEBGyHud+5ZhElxMWrbEkctfIWedxQXN6KD0EdTc3y857jE0tsP
rJF+QBCNRvKw/pICOzKJ/Jr/7i2PUT3tiI4M01S+dIAq4d3u71XoC94xBc6ScNUE
O5RZze+JPc7iO3T5vg==
-----END CERTIFICATE-----" >${DST}/ras/pca-root.crt
echo "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC608k/wEWScNI4
WP1zpP9dLphhGCcrvbfp/mnAQUgIwkk1Lqs9BkbF91/1UsEE8QhOSemVI4/u+mei
Oo9ZFYIXunPZP8YxEWXZqFwiJHgiVSjqRyweR8abzm9e+DSyAlkMuCQK1kJ8dvMF
MW/Vny13zQCSQtWh0L47Fnn0inxSzd/TPHhZNnNud9q0jdwjSmqxrNtNXaDNgmIB
V/o93zsl96x8Qs03vWVTRb4nPWZ89v8a3Y98eAZ8iHmaJ6ce1EWsu1fahSX132hM
wCHnmHS2MCp0cHwJvHdk4Uh2b3VE5ObkAkwSOCtuPkfiyQx2ggvETsvaLrg6cXlx
ua4TDaO5AgMBAAECggEBALKj2XXs2llZKZmZddfDOC4YZLnKh4HqqVXD38hmY4OE
is2gbzotqzSWAhooY8ne00tQn1nspC8lHjzf87uBtmAL98QOl+rJMPM7acV3y6tA
dJv3K/dUOFM4xAMyH+jqF83ysPvvvakXb+5SRBYmWyqHSfmQkIdmes8zAa/TT2c4
MGdf4YijcXQRHex5LHAO9RPYlWrNSyGfd2/38HCehavStvSs+eLz+UHcS0FUivXg
Z7MXK8ST4ThSywD6w4Zy/EuZT5dn9O7jUAdRHnKHibZdgojVHPSNgqozfFACyNmU
agQm/pgRqbCYIL+b3c0dsLrt+bkAKf8K1n7zFBzZchECgYEAwY0QsEFQGkCbH+73
RnZ1jtr0Qp5zXq9aRMTzJLpCttTzvrMLpWRasit8jMuElksdDdVjjUDfcdJSUyeE
/mCtgy52huYO6XWYhtai6coeaS1UXj59KfqXZaRcdcBFdZhsAFg87356cDBHSD8Z
itM1L4nhZ2kkXozYnjqR3MfZ91UCgYEA9xtaS9bkUVAihXxnwItfOGgMxnkNfUvr
wUFpvzPU1Z53IgBqR5zyUJBCSlUurLNfIFS/ZphlrxEaCM5wdT1WoZ8HnnJM8yOx
UTbFs92shV9ZCd4UNReepgatfk8bHvX9HK5Rzur9+wcNV+OoU7ZEEL/Ssu1DnN7y
eb47F2JTctUCgYA6YkwLbtgz4xMoEdSDa85QVlniEpvojuqi3eoeRRVEw333I1k6
/ceiAR4j9mw7TdMozhqmjFAarH/q13v1o8ITVRup25HZ+IAXBH3GGhMMVQEjIKRu
2kl6/pZpaqNJMr45aGSRNczHNLj74RTaXJWpjmTw5bVz0/av3CkNuTdVtQKBgQCo
4lnhUVo0NLeTUcY7M0X98CcjEqLkipnzN/jFA/CnmylC5NO+ZAa8hwu3b+Z5hBI0
r5cs0GVWtDJ96FG13xkxVtZHNUlgN3m9zthqKMv7T4I0G0LmUmFMiW3T0M7xZx/5
lS42ZCb3hQdalS57ICv+4otnXH+EXF+OUzRhtALijQKBgH/hC+eIgX3t3tnrrSrA
/l6Qx5BlKmHNRzoFUnzOlUMOU1kFMq8QW1QGQY1bk5x64sP4xNR6fYcxtwBNIO1H
7tjVDomfh04qDiYYEZtrBtrPz/5BaFlr0snMiz9DGJk1zGEzZvOECUYDUrLtydH1
Vl+qjN8egWj3vKrbvQ1kXAaD
-----END PRIVATE KEY-----" >${DST}/ras/pca-root.key
echo "-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgIIFsNTUFCxmkMwDQYJKoZIhvcNAQELBQAwNDEOMAwGA1UE
BhMFQ2hpbmExEDAOBgNVBAoTB0NvbXBhbnkxEDAOBgNVBAMTB1Jvb3QgQ0EwHhcN
MjExMjIzMDc1ODAzWhcNMjIxMjIzMDc1ODEzWjA3MQ4wDAYDVQQGEwVDaGluYTEQ
MA4GA1UEChMHQ29tcGFueTETMBEGA1UEAxMKcHJpdmFjeSBjYTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMr1msTG0hDhxnD7jva+oWccXEh/rljX8sKt
vZNiYesK7Hazf8ktXMur00FYf08pXa217EDdZEvr6GccbzaX9IyEdUVnWi15zT3G
FEHbLCZZnhPxQjtZjTYXbrCLSjibUxtp+oOnbDduEwI0JmlMgu1RjQNhHeO1qq1R
5072t/vIad/8EvNT6klW2hhh96erDJW5ONSiRmmivc24o/OAP36J6b3jpxKgNzQ3
ItZpjO1ZRWuDkZgvVArnILg9OZJ59r9kGjgWoEpbmA8+69Dhth/bndym7AzJ2qDZ
177ALsSRAHpA5xluwH0Gh98BE4YznjDhM6KsBqzSWtnLsLicILUCAwEAAaNaMFgw
DgYDVR0PAQH/BAQDAgEGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBIGA1UdEwEB/wQI
MAYBAf8CAQEwHQYDVR0OBBYEFPQgDpLlkKD56JPOawUgYWH9xrlAMA0GCSqGSIb3
DQEBCwUAA4IBAQAWXxcMoTmu1X1WnyeOxF+5X3eNP+lQ5mJruwBqAptvmBspybBZ
uo53VFsBfAJnoPoDQKYrVKhxGaBMXofzxv9IdrTvLmpkBsQJFgAPoQH4X737MXL+
EQR7qAf0Kpf6GC9ZBO2rlQDuwy4Z+mc25VHzrU/iOqWPbICmwhAnkbNf8MHFLDzS
fM/sYoURj4eJToWI4jtf3d46AFXtYgbYWqavI1qA2rV776oczKwlt2+oiIwg9GLj
dByNIC+yy21w+18ejiO2jo91RLv6KvSboKxu1+ejMc8xvPHNqcX5M0LL6EmaGhi6
WP+PyrEpFsPDO3DB/00z/zIwCk/o76sOQLAt
-----END CERTIFICATE-----" >${DST}/ras/pca-ek.crt
echo "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDK9ZrExtIQ4cZw
+472vqFnHFxIf65Y1/LCrb2TYmHrCux2s3/JLVzLq9NBWH9PKV2ttexA3WRL6+hn
HG82l/SMhHVFZ1otec09xhRB2ywmWZ4T8UI7WY02F26wi0o4m1MbafqDp2w3bhMC
NCZpTILtUY0DYR3jtaqtUedO9rf7yGnf/BLzU+pJVtoYYfenqwyVuTjUokZpor3N
uKPzgD9+iem946cSoDc0NyLWaYztWUVrg5GYL1QK5yC4PTmSefa/ZBo4FqBKW5gP
PuvQ4bYf253cpuwMydqg2de+wC7EkQB6QOcZbsB9BoffAROGM54w4TOirAas0lrZ
y7C4nCC1AgMBAAECggEAC9hz1QJJpmSXAWcdO/d6UhtMo4qYMWVBLO2Y/+4hCufT
T0ZAsgwsu1Jm/QxeOc+PQSE6DbseLHQzVzlIoGYUBtOASLG0iKzwNqfF7OYO2Joo
aL+O/wnF/R82/aTTiyQ9oH75+Q8feMi64UkL6N9nUNSOp2DWrsCemokKOAicSlyY
bvFRrbq6uhW9d7YlkZja07oGKGc7DeCulsrQbJa3HZD1z/oG/v3PWD6tosEJfn4S
Pk/6iCsP6VQZXvXfUa+YprTlC37pfUHIP/Lh0tNJzf3pvIvxJeZzdm28zby+Ejo8
qhd4Z2sy0OuvVY8FUXoH/pJZZshhcRr50rQcO5jZwQKBgQDVY2e1VTqNGo+OqhdO
2+MzbvMQ4N1GNmy6m3Je+B1B4HGG5EyBwrQglnBlStunMbiKLc7qojZH/XZOQ7Ov
FemR3H0RE4uKUHl1t0eH4KxLE8JbPSGNq702SOtt2PqYtMJiHCpC98cpSx1HErM5
4+GiqlomvcuTbehxlmOg1iorcQKBgQDzfRCK7LZYxyR9D65dDPC2gr5EKtNK85R7
1gVEja6jpbhRp1aP3EiPfBwmDtJ7amf+emUEpn1Kq8q6BcFF+1TfWDDfwUqztt7A
+zH3vDKy6MePKHo2TLrmAgyVKxKiHF50UI9YpNw/T3W32MvACMOHKgKI1giGa+2p
+IS2J07/hQKBgBBMrYlOX1CT7M9K8sjVRv+QxARQCNbqJVgDs7LJZQK5MDLLkYR/
6N5sX119YFXfGGeFpD6L8XWCSN0lkr4XAGZh3zPEuG3yQ7TYMSCR6tc5RSlO/Bck
PSm+XC1h25J6jDaOTDQdVRs0X6IkLYiIfZ29QXGgIcK7LHwwrp+EfGghAoGAUZC5
s/Ar/X1oicRxApbNJDaUCj3WXitOuFUvmpFjyUpAfonyA2slm3tV6qHYfKNehu71
XCNxoUv/M2WuIwVYnyDp7mrP3XgLEtaTHIwc57X288v5dKsriNVy5Z1yNoAOXCSI
gIdpiIPTyWyEhKXq6iJ2iuQ4It+Q0/l+a46rdgkCgYEA08CuLNZYwTxi+QiaS9dU
lnMjEkieXNeWjs1jj/YsbOmGuXj57xLVNDKX8/bRrZOY+3aR0LklUWMUZG/e4BTZ
Q1g8NACE9DsC5zdWK+jhKipDtvPoyGAV6V/PCvPciHE70XiJR2PfwO4YcXrVJGEj
jlMEWewO6KXvftd94RDRirE=
-----END PRIVATE KEY-----" >${DST}/ras/pca-ek.key
# change config
echo "default the key and cert..." | tee -a ${DST}/ras/echo.txt
### End Preparation  
cp ${DST}/ras/pca-ek.key ${DST}/ras/test-ek.key
sed -i 's/pcakeycertfile: ""/pcakeycertfile: .\/pca-ek.crt/g' ${DST}/ras/config.yaml
sed -i 's/pcaprivkeyfile: ""/pcaprivkeyfile: .\/pca-ek.key/g' ${DST}/ras/config.yaml
sed -i 's/rootkeycertfile: ""/rootkeycertfile: .\/pca-root.crt/g' ${DST}/ras/config.yaml
sed -i 's/rootprivkeyfile: ""/rootprivkeyfile: .\/pca-root.key/g' ${DST}/ras/config.yaml

### start launching binaries for testing
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ./ras -T &>>${DST}/ras/echo.txt ; ./ras -v &>>${DST}/ras/echo.txt ;)&
# start number of rac clients
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t -v &>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent
echo "test DONE!!!" | tee -a ${DST}/control.txt

### check the ek cert's log is only one
### cat ${DST}/rac-1/echo.txt|grep 'ok' |wc -l
ECCOUNT=$(grep 'load EK certificate success' ${DST}/rac-1/echo.txt |wc -l)
echo "generateEKCert count: ${ECCOUNT}" | tee -a ${DST}/control.txt

#cat two file
diff ${DST}/ras/pca-ek.key ${DST}/ras/test-ek.key
if (( $? == 0 ))
then
    echo "Both file are same"
    KEYSAME=1
else 
    echo "not same"
    KEYSAME=0
fi
### list the log
### tail -f ${DST}/rac-1/echo.txt
### check the ekCert's file is not null
if test -s ${DST}/rac-1/ectest.crt;then
    ECEMPTY=0
    echo "ectest is not empty" | tee -a ${DST}/control.txt
else
    ECEMPTY=1
    echo "ectest is empty" | tee -a ${DST}/control.txt
fi
### check the ik cert's log is only one
ICCOUNT=$(grep 'load IK certificate success' ${DST}/rac-1/echo.txt |wc -l)
echo "generateIKCert count: ${ICCOUNT}" | tee -a ${DST}/control.txt
### check the ekCert's file is not null

if test -s ${DST}/rac-1/ictest.crt;then
    ICEMPTY=0
    echo "ictest is not empty" | tee -a ${DST}/control.txt
else
    ICEMPTY=1
    echo "ictest is empty" | tee -a ${DST}/control.txt
fi

if (( ${ECCOUNT} == 1 )) && (( ${ICCOUNT} == 1 )) && (( ${ECEMPTY} == 0 )) && (( ${ICEMPTY} == 0 )) && (( ${KEYSAME} == 1 ))
then
    echo "test succeeded!"
    exit 0
else
    echo "test failed!"
    exit 1
fi