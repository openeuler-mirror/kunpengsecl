package katools

import (
	"os"
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	//"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/kcmstools"
)

var (
	addr		=	"address"
	id	int64	=	1
	certPath    =	"../cert/"
	kcmFileName =	"kcm.crt"
	caFileName  =	"ca.crt"
)

var (
rpy = []byte{
	0x00, 0x0b, 0x25, 0x7f, 0x26, 0x0b, 0x02, 0x18, 0xf2, 0x15, 0xda, 0x02, 0xf9, 0xba, 0x7c, 0xf2, 0x68,
	0x15, 0x47, 0x80, 0x47, 0xa9, 0xaf, 0x60, 0x04, 0x88, 0x8e, 0x57, 0xfb, 0x34, 0x02, 0xd0, 0xf3, 0xf0}
)

const (
	kcmCert = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=CN, ST=Shanghai, L=Shanghai, O=Huawei, CN=ca
        Validity
            Not Before: Mar  5 15:12:10 2023 GMT
            Not After : Feb 24 15:12:10 2024 GMT
        Subject: C=CN, ST=Shanghai, L=Shanghai, O=Huawei, CN=kcm
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:b4:be:9b:c2:c9:97:f4:bc:51:a1:45:f6:2d:34:
                    8a:fc:34:03:af:52:77:14:c8:3d:35:f1:28:bd:a2:
                    53:49:98:5b:36:f4:f9:76:e6:6a:59:42:52:38:7a:
                    c1:20:f7:f3:81:53:e1:5b:fc:00:f6:63:c4:d3:bc:
                    91:2c:dc:41:ba:94:43:1c:c1:e2:1a:cb:c1:1b:47:
                    45:4e:fe:70:8c:92:0c:bc:ea:07:a6:71:27:e5:57:
                    06:48:75:82:14:83:12:76:f3:34:f2:a0:50:c7:ee:
                    6c:18:00:f7:a6:71:8c:f3:63:32:7f:e8:8c:34:7f:
                    5c:c9:d7:2f:4a:93:91:ea:8a:00:0a:e5:32:84:6f:
                    e9:c1:2b:fd:f8:25:98:2e:28:ea:c0:7d:e2:a3:c9:
                    0f:75:59:25:8c:fe:f0:a0:c9:d0:8d:83:28:e5:33:
                    39:e3:be:44:66:98:5e:31:6e:05:44:d6:e6:36:c5:
                    4c:4c:64:02:89:5b:68:01:e7:6c:ec:5a:73:fd:b4:
                    18:f8:be:15:5b:55:a2:7e:e9:d3:3e:a1:69:1e:4c:
                    bd:e6:89:1c:05:f1:e7:03:79:71:f9:d8:57:25:a1:
                    4b:51:de:32:c0:cd:59:92:a2:bb:e8:71:f4:23:b7:
                    17:f0:94:8d:00:47:07:ba:1a:5b:07:5f:a1:61:50:
                    14:41
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Comment: 
                OpenSSL Generated Certificate
            X509v3 Subject Key Identifier: 
                81:04:CB:A4:F9:A8:85:F9:49:5A:65:CB:C5:DF:05:34:FC:24:CA:95
            X509v3 Authority Key Identifier: 
                keyid:41:FD:15:7A:E1:6D:64:96:0F:27:64:14:0E:04:3D:0A:90:92:2C:41

    Signature Algorithm: sha256WithRSAEncryption
         77:0e:da:f3:f5:fb:40:e0:72:49:3f:48:46:ff:20:97:87:05:
         0c:9f:6b:9e:be:af:79:67:2c:f8:bc:88:a1:c2:3e:4e:05:42:
         09:7d:10:81:1e:06:82:3e:55:4b:2e:33:8d:e0:f4:7a:31:c3:
         25:4b:9a:e0:6d:1b:9c:c2:b4:45:48:f6:01:fa:ea:b5:1d:7f:
         1d:48:28:09:21:48:07:58:13:d6:60:0f:05:17:8b:5a:f6:cd:
         29:b4:55:ca:db:29:0f:34:63:61:fc:ef:f0:f8:6e:54:94:b7:
         ff:5b:b4:12:99:22:5c:3b:16:2f:e9:f3:0a:0b:66:18:46:c1:
         8a:e2:27:ef:1d:84:a4:0d:96:01:cf:12:59:e2:fd:67:ba:19:
         dd:27:9a:aa:9a:cb:5b:65:dc:1f:70:cb:66:8b:2c:b0:fa:b2:
         40:be:57:59:b9:ad:e3:b5:8f:fc:7f:b2:a8:80:52:01:57:31:
         be:44:bd:06:c7:ed:94:3e:10:93:23:0d:af:21:df:39:9f:5d:
         39:3f:63:33:7e:02:c9:7f:81:81:a3:32:ce:58:59:8c:9e:82:
         7b:2a:e1:6d:cb:b3:a4:86:5d:51:e6:08:84:fc:06:ae:ac:f1:
         de:52:39:be:62:c6:60:5a:57:09:bc:39:90:16:5e:0f:64:f7:
         b1:9a:f3:53
-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJDTjER
MA8GA1UECAwIU2hhbmdoYWkxETAPBgNVBAcMCFNoYW5naGFpMQ8wDQYDVQQKDAZI
dWF3ZWkxCzAJBgNVBAMMAmNhMB4XDTIzMDMwNTE1MTIxMFoXDTI0MDIyNDE1MTIx
MFowUjELMAkGA1UEBhMCQ04xETAPBgNVBAgMCFNoYW5naGFpMREwDwYDVQQHDAhT
aGFuZ2hhaTEPMA0GA1UECgwGSHVhd2VpMQwwCgYDVQQDDANrY20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0vpvCyZf0vFGhRfYtNIr8NAOvUncUyD01
8Si9olNJmFs29Pl25mpZQlI4esEg9/OBU+Fb/AD2Y8TTvJEs3EG6lEMcweIay8Eb
R0VO/nCMkgy86gemcSflVwZIdYIUgxJ28zTyoFDH7mwYAPemcYzzYzJ/6Iw0f1zJ
1y9Kk5HqigAK5TKEb+nBK/34JZguKOrAfeKjyQ91WSWM/vCgydCNgyjlMznjvkRm
mF4xbgVE1uY2xUxMZAKJW2gB52zsWnP9tBj4vhVbVaJ+6dM+oWkeTL3miRwF8ecD
eXH52FcloUtR3jLAzVmSorvocfQjtxfwlI0ARwe6GlsHX6FhUBRBAgMBAAGjezB5
MAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENl
cnRpZmljYXRlMB0GA1UdDgQWBBSBBMuk+aiF+UlaZcvF3wU0/CTKlTAfBgNVHSME
GDAWgBRB/RV64W1klg8nZBQOBD0KkJIsQTANBgkqhkiG9w0BAQsFAAOCAQEAdw7a
8/X7QOByST9IRv8gl4cFDJ9rnr6veWcs+LyIocI+TgVCCX0QgR4Ggj5VSy4zjeD0
ejHDJUua4G0bnMK0RUj2AfrqtR1/HUgoCSFIB1gT1mAPBReLWvbNKbRVytspDzRj
Yfzv8PhuVJS3/1u0EpkiXDsWL+nzCgtmGEbBiuIn7x2EpA2WAc8SWeL9Z7oZ3Sea
qprLW2XcH3DLZosssPqyQL5XWbmt47WP/H+yqIBSAVcxvkS9BsftlD4QkyMNryHf
OZ9dOT9jM34CyX+BgaMyzlhZjJ6CeyrhbcuzpIZdUeYIhPwGrqzx3lI5vmLGYFpX
Cbw5kBZeD2T3sZrzUw==
-----END CERTIFICATE-----`
)

const (
	caTestCert = `
-----BEGIN CERTIFICATE-----
MIIDgzCCAmugAwIBAgIUY7CJG5rYIgNrCVUKaxB19LhZ57owDQYJKoZIhvcNAQEL
BQAwUTELMAkGA1UEBhMCQ04xETAPBgNVBAgMCFNoYW5naGFpMREwDwYDVQQHDAhT
aGFuZ2hhaTEPMA0GA1UECgwGSHVhd2VpMQswCQYDVQQDDAJjYTAeFw0yMzAzMDUx
NTEyMDhaFw0yNDAyMjQxNTEyMDhaMFExCzAJBgNVBAYTAkNOMREwDwYDVQQIDAhT
aGFuZ2hhaTERMA8GA1UEBwwIU2hhbmdoYWkxDzANBgNVBAoMBkh1YXdlaTELMAkG
A1UEAwwCY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDXziH+1e74
R/2dOtQwIiefu5SZ1rpSqITBdV0ug3T66latw5WSxfVeLSsThZK4g/86Zmy7PYdl
XzRrDL+zZS+qjsC5ykKlVIEobEootPo67BTz0060NcqcUKwKpHJP8JJpo7+553+8
sOljj5cV7Ioa30ibZgSJpzESBRmN+0O1iOVsIkDYk6KwCGAXcf2WYUSdiIoQphKH
EKfftBLpCO4/XZevAbSOuZnLA+f7E5CFlBFQkSMkZQEY0mxSFWhgzZXbKE5jXXT5
WJ5ErmKRhcRkLEmENbv9xhZGZCoEsyRNYFOPtwfa/NyVrKk52dGyHD5A6EDIdEHf
AaKGBQPaZ25XAgMBAAGjUzBRMB0GA1UdDgQWBBRB/RV64W1klg8nZBQOBD0KkJIs
QTAfBgNVHSMEGDAWgBRB/RV64W1klg8nZBQOBD0KkJIsQTAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDUMi9ub0Zl37Pm8j5B7YbZK6u3E1KC8zX/
kpyxq8UbquDizHcBkiWJH42C1T62k26rlbPn4Mt95XQdvJbP8RvSw+tbGCWLTEiZ
TPeekW6+EkjBJcq/vEucqTRUIPNaBx41m/bhwu6Iyk322Ef76uWZpW7i1LDDg1RF
0Y20mpaPfz4QDM5AFua6Uw8Mj3Rco2eykdOuxpLBnsJQugzvWlPkz4HSmiGXJqqj
AcMaRWCaMNG791l6wRb4+Ulehf9txLs+L/e7R3jSVxELXb8LIXvgBVX5kXj3Az68
oNL/kG2dujz4O4n+pV0EPCuQzogyVtBq4sqP08V8A26lhdtTrduV
-----END CERTIFICATE-----`
)

func TestValidateCert(t *testing.T){
	CreateClientConfigFile()
	defer RemoveConfigFile()
	PrepareConfig()
	loadConfigs()
	err := kcmstools.SaveCert([]byte(kcmCert), certPath, kcmFileName)
	if err != nil {
		t.Errorf("save KCM Cert failed, error: %v", err)
	}
	err = kcmstools.SaveCert([]byte(caTestCert), certPath, caFileName)
	if err != nil {
		t.Errorf("save CA Cert failed, error: %v", err)
	}
	defer os.RemoveAll(certPath)
	kcmReadCert, err := kcmstools.ReadCert(certPath + kcmFileName)
	kcmDecodeCert, _, err := cryptotools.DecodeKeyCertFromPEM(kcmReadCert)
	if err != nil {
		t.Errorf("fail to decode kcm cert, %v", err)
	}
	caDecodeCert, _, err := cryptotools.DecodeKeyCertFromFile(certPath + caFileName)
	if err != nil {
		t.Errorf("fail to decode ca cert, %v", err)
	}
	err = validateCert(kcmDecodeCert, caDecodeCert)
	if err != nil {
		t.Errorf("validate kcm cert error, %s", err)
	}
}


