package ractools

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/pca"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	HandleOwner     tpmutil.Handle = 0x40000001
	testImaLogPath                 = "../cmd/raagent/ascii_runtime_measurements"
	testBiosLogPath                = "../cmd/raagent/binary_bios_measurements"
	AesKeySize                     = 16
	Encrypt_Alg                    = "AES128-CBC"
	AlgAES                         = 0x0006
	AlgCBC                         = 0x0042
	pcaKeyCertPem                  = `
-----BEGIN CERTIFICATE-----
MIIDOTCCAiGgAwIBAgIBATANBgkqhkiG9w0BAQsFADA0MQ4wDAYDVQQGEwVDaGlu
YTEQMA4GA1UEChMHQ29tcGFueTEQMA4GA1UEAxMHUm9vdCBDQTAeFw0yMTEyMTQx
MjIxMjdaFw0zMTEyMTQxMjIxMzdaMDQxDjAMBgNVBAYTBUNoaW5hMRAwDgYDVQQK
EwdDb21wYW55MRAwDgYDVQQDEwdSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAuvLnEdLj//7Z+zjbVmXTnkJKX/RIaw7jIMYl4XkEeGH2vwXe
nntLydT8ZNKmKde6jhYAJlDK19oYJlttH9w9UDCMYYMY2FugUX77e+jLdJJoqsI7
CCNaZV5yejgoQfQtSUqEbzr7iE1FkEq+m9xp/G2Rv3ZWDS4qOiouuQm13lVVpMdq
32bMc87b2QNdEX01vnyEpljj594G0OAUUIU68i3F1XlNR2SHJVaRaX5oUPzMguwc
1Z5MCP84vbdLtoB2dMurkPH1ZQD3sXWMAhA8Q23o/sH13g0kIcbf9+2gYBFvINC9
ftaCYrk+pS5MLLp2u/G9cixA2E5y7tabsiX5TwIDAQABo1YwVDAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0lBAgwBgYEVR0lADASBgNVHRMBAf8ECDAGAQH/AgECMB0GA1Ud
DgQWBBRQnyfM6sqwlJrkqEiepafgdr8nYjANBgkqhkiG9w0BAQsFAAOCAQEAmeTh
Q89l1dT4t+8yDu9wjh6JMx/ZGWFV7NYWyXY5LtC1ktMJn/amLcrLdClv1Q1XSM4D
mBBhHRJ8yfrA+mbuBR4549LbW2/KobkSeFy5lQzhrQx8PeeUAFQqaLdHgDfxk68y
DASl60uLzqLgnmyam0SktfLZ++FXoqGfnZaD1kHYcouTMDTp6BDutjFhk3ZluJhU
SFmsV+BlxkhH56wBuEVOYcIL5q/Pc88DemuqyudvZansUkDfK49Uw4FklkCJ4JSz
eMY6tgoJrExOGdt696AkHQCtnXc0NdMbi7m41b64biZOYTW7fl6i06GDUhswDGyc
AvW5Pw09l1bOHAqH6g==
-----END CERTIFICATE-----`
	pcaPrivKeyPem = `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCS/DI+95XtVoG4
oaEXax5vCECF2uV6seDCIoGk/+3o2wbYkLhdxJ86f+xDxCawV7ZoUzGTosbw38jp
s40tQ86x3o3pNLsZA8zcZcNqwLCFRucaVQAKp1pvrNVurAyRZb5BY8GA0EXIPLMc
wgcENZEGhJ0E6x/jR+rc96EqzCGgP8mROUNT1mPhmU7vasfopAwxoCqWL+v0BixO
k1N9torXWcOglkwM9Cj4fMK1jHHK9dzm7uGAxwcbbjZ0wP+7EIDfv3A0Y1Fmd/m2
h4/0L5oPPrP2kFBxn7PXyQGkIiCTQqx/33/SJNqwIScTKz+NYm2vh4rmLAf+JhtT
keAXIuZ5AgMBAAECggEAELRIoY9Rop9qLqlvvVGXK9csPgoaek8s0+NICJBtYUFD
DemkikOGNQfEug7YtsHBISoTQEwHf+hu1OBq8vH5040PY6lyee1Mot+NzdwIM51T
NlLiplNOm9JwjxtOcle1v4iuvQzuYUtEr8f9NCVCThNUJPLztMi/kE00K8D3MVbi
YeVRUg+eWIWOUsy3n0XhHl6aVI0nbIdzJ/tYFsrqfC0PqmP0zxzu77bUyvFhiztT
euPlPL1Dg+uNK9f6m0lOehwxGiFi0Xu5PHvf9b5ZmUV3XQLEbXLURg97SkWIpfDL
F6xT4DuASooOe4VkRbnoLjEi42KRwIz1VlV5BTh7YQKBgQDAbf5ZqqqFJhtprDRV
JHle2cOBGPcMSzm7tMa3zHmZRfxQ5OX+Op2L8S8HlJCWJn01FtY6Zu5igpF507ND
dTxS5/oHNTpppU6cFMYOMfc93iR1EbL0A+suIjc6pkoCG8Dzl5cQlsfgTsLQBgCK
Gh+jFosf9iRzPMnUI0LXNucp0wKBgQDDiufCotCQopwuqwxLTtbL/oFY0EgiselS
pfMaG0Y/sQCmcmvc+iZJAIGLxcFo0fMQFskuXa29B278KzApDMZey68G45OzItPB
cKKOoHTgd4cc/LbQvBkacGwPP884MeOTxRs3h9O/mntzu13cY6ZnVDKM4P5UlE8m
51ghh+pTAwKBgDre69ve3MBTgjt4FaKewAsGsEtEqgA223jTu5/rjKAZyzGsdbir
khuINA0rpHhrWg7t56iCaRf2Pi95VvSiX0w18EZYQICltEEIEfexzaQ93AV83rTM
phy9Fwx4Z1fxybw8elj26Dt1nSArVerqRxeMBBBJK6mdxVmDWCWjhGFFAoGANTC8
uEoXl7BT8bHfh0Cr1xOk1abaaG2ivTOc/DX9Fugr+BrZ0mNNNMBpfL7PTJcHmhHI
qc8bqnayLvAEirYJ49FeC+6tx6WqmkzsOwXUpRZ+b1ki1YbFAVchXciKsouHjzOn
oqRU6iK4gBOwhXmp0yOpGH8/T3yER13YsE5LZEcCgYEAqZweJNzK+bwUEnKLQwoD
ATq4dH7EiYwp2zjaS8wV4b/thGN4cCXfaZwus6TZCnqshxTQfMMmpM4YGzas1pt/
0pHrfSyDJg1XTKOPatDhPSrPswW7xPng8caC/wJOxmiSWbgaXBHLADEjIK2+P+LK
bcCNb6Mz16HN1bP6kjoKTmA=
-----END PRIVATE KEY-----`
)

var (
	pcrSelection        = pcrSelectionAll
	nonce        uint64 = 1
	clientId     int64  = 1
	testMode            = true
)

func TestCreateTrustReport(t *testing.T) {
	TpmConf := TPMConfig{}
	TpmConf.IMALogPath = testImaLogPath
	TpmConf.BIOSLogPath = testBiosLogPath
	TpmConf.ReportHashAlg = ""
	Tpm, err := OpenTPM(!testMode, &TpmConf)
	if err != nil {
		t.Errorf("OpenTpm failed, err: %v", err)
		return
	}
	defer Tpm.Close()

	//create EK,Ak,TrustReport
	err = Tpm.GenerateEKey()
	if err != nil {
		t.Errorf("Create Ek failed: %s", err)
	}
	err = Tpm.GenerateIKey()
	if err != nil {
		t.Errorf("Create Ik failed: %s", err)
	}
	got, err := Tpm.GetTrustReport(nonce, clientId)
	if err != nil {
		t.Errorf("CreateTrustReport failed: %s", err)
	}

	//compare pcrInfo
	pcrmp, _ := Tpm.readPcrs(pcrSelection)
	pcrValues := map[int]string{}
	for key, pcr := range pcrmp {
		pcrValues[key] = hex.EncodeToString(pcr)
	}
	for i := range pcrmp {
		if got.PcrInfo.Values[int32(i)] != pcrValues[i] {
			t.Errorf("PCRs are not equal, got %v want %v", []byte(got.PcrInfo.Values[(int32)(i)]), pcrValues[i])
		}
	}

	attestation, _, err := tpm2.Quote(Tpm.dev, Tpm.IK.Handle, Tpm.IK.Password, emptyPassword,
		nil, pcrSelection, tpm2.AlgNull)
	if err != nil {
		t.Errorf("Quote failed: %s", err)
	}
	_, err = tpm2.DecodeAttestationData(attestation)
	if err != nil {
		t.Errorf("DecodeAttestationData failed: %s", err)
	}
}

func TestNVRAM(t *testing.T) {
	var testNVIndex uint32 = 0x01C00030
	TpmConf := TPMConfig{}
	TpmConf.IMALogPath = TestImaLogPath
	TpmConf.BIOSLogPath = TestBiosLogPath
	TpmConf.ReportHashAlg = ""
	Tpm, err := OpenTPM(!testMode, &TpmConf)
	if err != nil {
		t.Errorf("OpenTpm failed, err: %v", err)
		return
	}
	defer Tpm.Close()

	priv, _ := rsa.GenerateKey(rand.Reader, pca.RsaKeySize)
	// sign by root ca
	ekDer, err := x509.CreateCertificate(rand.Reader, &pca.RootTemplate, &pca.RootTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Errorf("CreateCertificate failed, err: %v", err)
	}

	Tpm.UndefineNVRAM(testNVIndex)
	Tpm.DefineNVRAM(testNVIndex, uint16(len(ekDer)))
	Tpm.WriteNVRAM(testNVIndex, ekDer)
	ekCert, err := Tpm.ReadNVRAM(testNVIndex)
	if err != nil {
		t.Errorf("ReadEKCert failed, err: %v", err)
	}
	Tpm.LoadEKeyCert()
	if !bytes.Equal(ekCert, ekDer) {
		t.Errorf("EKCert are not equal, got: %v, want: %v \n", ekCert, ekDer)
	}
	Tpm.UndefineNVRAM(testNVIndex)
}

func TestActivateIKCert(t *testing.T) {
	TpmConf := TPMConfig{}
	Tpm, err := OpenTPM(!testMode, &TpmConf)
	if err != nil {
		t.Errorf("OpenTpm failed, err: %v", err)
		return
	}
	defer Tpm.Close()
	err = Tpm.GenerateEKey()
	if err != nil {
		t.Errorf("Create Ek failed: %s", err)
	}
	err = Tpm.GenerateIKey()
	if err != nil {
		t.Errorf("Create Ik failed: %s", err)
	}
	ikPubDer, err := x509.MarshalPKIXPublicKey(Tpm.IK.Pub)
	if err != nil {
		t.Errorf("can't get Ik public der data, error: %s", err)
	}
	template := x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(1, 0, 0),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:           false,
		MaxPathLenZero: true,
	}

	pcaKeyCert, _, err := pca.DecodeKeyCertFromPEM([]byte(pcaKeyCertPem))
	if err != nil {
		t.Errorf("PCA: can't get pcaKeyCert, error: %s", err)
	}
	pcaPrivKey, _, err := pca.DecodePrivateKeyFromPEM([]byte(pcaPrivKeyPem))
	if err != nil {
		t.Errorf("PCA: can't get pcaPrivKey, error: %s", err)
	}
	ikCertDer, err := pca.GenerateCertificate(&template, pcaKeyCert, ikPubDer, pcaPrivKey)
	if err != nil {
		t.Errorf("PCA: can't get ikCertDer, error: %s", err)
	}

	key, _ := pca.GetRandomBytes(AesKeySize)
	iv, _ := pca.GetRandomBytes(AesKeySize)
	encIKCert, err := pca.SymmetricEncrypt(AlgAES, AlgCBC, key, iv, ikCertDer)
	if err != nil {
		t.Errorf("PCA: SymmetricEncrypt failed, error: %s", err)
	}
	encKeyBlob, encSecret, err := tpm2.MakeCredential(Tpm.dev, Tpm.EK.Handle, key, Tpm.IK.Name)
	if err != nil {
		t.Errorf("MakeCredential failed, error: %s", err)
	}
	_, err = Tpm.ActivateIKCert(&IKCertInput{
		CredBlob:        encKeyBlob,
		EncryptedSecret: encSecret,
		EncryptedCert:   encIKCert,
		DecryptAlg:      Encrypt_Alg,
		DecryptParam:    iv,
	})
	if err != nil {
		t.Errorf("ActivateIKCert failed, error: %s", err)
	}
}
func TestPreparePCRsTest(t *testing.T) {
	TpmConf := TPMConfig{}
	TpmConf.IMALogPath = TestImaLogPath
	TpmConf.BIOSLogPath = TestBiosLogPath
	TpmConf.ReportHashAlg = ""
	Tpm, err := OpenTPM(!testMode, &TpmConf)
	if err != nil {
		t.Errorf("OpenTpm failed, err: %v", err)
		return
	}
	defer Tpm.Close()
}
