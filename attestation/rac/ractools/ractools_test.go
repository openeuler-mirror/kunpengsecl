package ractools

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/pca"
	"github.com/google/go-tpm-tools/simulator"
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
	algSha1Str                     = "sha1"
	algSha256Str                   = "sha256"
)

var (
	pcrSelection        = pcrSelectionAll
	nonce        uint64 = 1
	clientId     int64  = 1
	testMode            = true
)

func TestCreateTrustReport(t *testing.T) {
	test.CreateClientConfigFile()
	config.GetDefault(config.ConfClient)
	defer test.RemoveConfigFile()

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
	test.CreateClientConfigFile()
	config.GetDefault(config.ConfClient)
	defer test.RemoveConfigFile()

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

func GenerateCertificate(t *testing.T) (crypto.PrivateKey, *x509.Certificate) {
	priv, err := rsa.GenerateKey(rand.Reader, pca.RsaKeySize)
	if err != nil {
		t.Fatal(err)
	}
	pubDer, err := pca.EncodeKeyPubPartToDER(priv)
	if err != nil {
		t.Fatalf("can't encode pubkey to Pem, %v", err)
	}
	certDer, err := pca.GenerateCertificate(&pca.RootTemplate, &pca.RootTemplate, pubDer, priv)
	if err != nil {
		t.Fatalf("can't generate certificate, %v", err)
	}
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		t.Fatalf("can't parse certificate, %v", err)
	}
	return priv, cert
}

func TestActivateIKCert(t *testing.T) {
	test.CreateClientConfigFile()
	config.GetDefault(config.ConfClient)
	defer test.RemoveConfigFile()

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

	pcaPrivKey, pcaKeyCert := GenerateCertificate(t)
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

func prepareManifestFiles(imaFile, biosFile string, imaManifest, biosManifest []byte) {
	_ = ioutil.WriteFile(imaFile, imaManifest, 0600)
	_ = ioutil.WriteFile(biosFile, biosManifest, 0600)
}

func removeManifestFiles(imaFile string, biosFile string) {
	_ = os.Remove(imaFile)
	_ = os.Remove(biosFile)
}

func DumpPCRs(tpm *TPM, t *testing.T) {
	pcrs, err := tpm.readPcrs(pcrSelectionAll)
	if err != nil {
		t.Errorf("read PCRs failed, err: %v", err)
	}
	for i := range pcrs {
		fmt.Println("pcr", i, hex.EncodeToString(pcrs[i]))
	}
	fmt.Println()
}

func comparePCRs(pcrs1 map[int][]byte, pcrs2 map[int]string) error {
	if len(pcrs1) != len(pcrs2) {
		return fmt.Errorf("length mismatching")
	}
	for k := range pcrs1 {
		pcr := hex.EncodeToString(pcrs1[k])
		if pcr != pcrs2[k] {
			return fmt.Errorf("pcr%d mismatching", k)
		}
	}
	return nil
}

var testBiosManifest = []byte{0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x25, 0x0, 0x0, 0x0, 0x53, 0x70, 0x65, 0x63, 0x20, 0x49, 0x44, 0x20, 0x45,
	0x76, 0x65, 0x6e, 0x74, 0x30, 0x33, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x2, 0x2, 0x0, 0x0, 0x0, 0x4, 0x0, 0x14,
	0x0, 0xb, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x4, 0x0, 0x53, 0x93,
	0x3b, 0xe8, 0x90, 0x80, 0xc1, 0xfd, 0xc6, 0x35, 0x2b, 0xb6, 0xc8, 0xe7, 0x87, 0x99, 0xd0, 0x1f, 0x23, 0x0, 0xb,
	0x0, 0x77, 0xe4, 0x1e, 0x1a, 0x6e, 0x98, 0xf7, 0x16, 0xa, 0x8b, 0xa8, 0x5d, 0x1b, 0x68, 0x1d, 0xf8, 0x4b, 0x74,
	0x9f, 0x88, 0xff, 0xd5, 0x85, 0x61, 0x2e, 0x14, 0x54, 0x21, 0xb4, 0x2e, 0xe5, 0x81, 0xa, 0x0, 0x0, 0x0, 0x31,
	0x0, 0x2e, 0x0, 0x30, 0x0, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x80, 0x2, 0x0, 0x0, 0x0,
	0x4, 0x0, 0xc6, 0xda, 0xaa, 0xf6, 0x6e, 0xfc, 0xe1, 0x2d, 0x87, 0x25, 0x4e, 0xb5, 0xdc, 0x4b, 0xd2, 0xb8,
	0xad, 0xd, 0xc0, 0x85, 0xb, 0x0, 0x72, 0x3e, 0xd4, 0xcf, 0x5a, 0xcc, 0xf6, 0x5d, 0x8f, 0xe6, 0x84, 0x49,
	0x1d, 0x5c, 0xb1, 0xf6, 0x16, 0x7f, 0x63, 0x15, 0xfa, 0x55, 0x3d, 0x57, 0xfb, 0xf9, 0x46, 0x66, 0x7b, 0x7,
	0xc2, 0xad, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x5f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x80, 0x2, 0x0, 0x0, 0x0, 0x4, 0x0, 0x2f, 0x20, 0x11, 0x2a, 0x3f,
	0x55, 0x39, 0x8b, 0x20, 0x8e, 0xc, 0x42, 0x68, 0x13, 0x89, 0xb4, 0xcb, 0x5b, 0x18, 0x23, 0xb, 0x0, 0xce,
	0x9c, 0xe3, 0x86, 0xb5, 0x2e, 0x9, 0x9f, 0x30, 0x19, 0xe5, 0x12, 0xa0, 0xd6, 0x6, 0x2d, 0x6b, 0x56, 0xe,
	0xfe, 0x4f, 0xf3, 0xe5, 0x66, 0x1c, 0x75, 0x25, 0xe2, 0xf9, 0xc2, 0x63, 0xdf, 0x34, 0x0, 0x0, 0x0, 0x61,
	0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0xd, 0x0, 0xe0, 0x98, 0x3, 0x2b, 0x8c, 0xa, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x53, 0x0, 0x65, 0x0, 0x63, 0x0, 0x75, 0x0, 0x72,
	0x0, 0x65, 0x0, 0x42, 0x0, 0x6f, 0x0, 0x6f, 0x0, 0x74, 0x0}

const testIMAManifestIMA = `10 dd6ec4b71368cfe1d49756ba7cdf0260ae65472c ima 08b63c264eb87c8403cf87c57b3c3112de384e52 boot_aggregate
10 ef7a0aff83dd46603ebd13d1d789445365adb3b3 ima 0f8b3432535d5eab912ad3ba744507e35e3617c1 /init
10 247dba6fc82b346803660382d1973c019243e59f ima 747acb096b906392a62734916e0bb39cef540931 ld-2.9.so
10 341de30a46fa55976b26e55e0e19ad22b5712dcb ima 326045fc3d74d8c8b23ac8ec0a4d03fdacd9618a ld.so.cache`
const testIMAManifestIMANGSha1 = `10 7df19938dd69f3d8e6c1d6b0b52978dca80facc0 ima-ng sha1:08b63c264eb87c8403cf87c57b3c3112de384e52 boot_aggregate
10 efe9f432379df6f9990187cd338f6ccc97126281 ima-ng sha1:0f8b3432535d5eab912ad3ba744507e35e3617c1 /init
10 56adff5cf88e8be8f2049c060d18855cc69bb19a ima-ng sha1:747acb096b906392a62734916e0bb39cef540931 ld-2.9.so
10 e314618c2f92bb9307d4f21037e6aad919784438 ima-ng sha1:326045fc3d74d8c8b23ac8ec0a4d03fdacd9618a ld.so.cache`
const testIMAManifestIMANGSha256 = `10 a5fee565ab35b4ea0c6cf9e2147d2a09debd1432 ima-ng sha256:8a19a149fc98679a18d0144569414452377128ba120156925ebaa4fffd55b69f boot_aggregate
10 19a6b9f6a597c95318540cc69ec1e2046c02359f ima-ng sha256:0f8b3432535d5eab912ad3ba744507e35e3617c10f8b3432535d5eab912ad3ba /init
10 55e549d23f371aca88fd0082d65fdee18316c984 ima-ng sha256:747acb096b906392a62734916e0bb39cef540931747acb096b906392a6273491 ld-2.9.so
10 6abe9359127dea2a47c055e0eba7485cdcf26f01 ima-ng sha256:326045fc3d74d8c8b23ac8ec0a4d03fdacd9618a326045fc3d74d8c8b23ac8ec ld.so.cache`
const sha1HashAllZero = "0000000000000000000000000000000000000000"
const sha1HashAllFF = "ffffffffffffffffffffffffffffffffffffffff"
const sha256HashAllZero = "0000000000000000000000000000000000000000000000000000000000000000"
const sha256HashAllFF = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

var testExpectedPCRsIMA = map[int]string{
	0:  "3029fb5bd5c012a9762ea5b7187d0e843fe2a274",
	1:  sha1HashAllZero,
	2:  sha1HashAllZero,
	3:  sha1HashAllZero,
	4:  sha1HashAllZero,
	5:  sha1HashAllZero,
	6:  sha1HashAllZero,
	7:  "a257b91f840ca822ddda6f023d494c56a3a15823",
	8:  sha1HashAllZero,
	9:  sha1HashAllZero,
	10: "a5f9dc672a31a58c950d12a75fb15e7f2dc1633c",
	11: sha1HashAllZero,
	12: sha1HashAllZero,
	13: sha1HashAllZero,
	14: sha1HashAllZero,
	15: sha1HashAllZero,
	16: sha1HashAllZero,
	17: sha1HashAllFF,
	18: sha1HashAllFF,
	19: sha1HashAllFF,
	20: sha1HashAllFF,
	21: sha1HashAllFF,
	22: sha1HashAllFF,
	23: sha1HashAllZero,
}

var testExpectedPCRsIMANGSha1 = map[int]string{
	0:  "3029fb5bd5c012a9762ea5b7187d0e843fe2a274",
	1:  sha1HashAllZero,
	2:  sha1HashAllZero,
	3:  sha1HashAllZero,
	4:  sha1HashAllZero,
	5:  sha1HashAllZero,
	6:  sha1HashAllZero,
	7:  "a257b91f840ca822ddda6f023d494c56a3a15823",
	8:  sha1HashAllZero,
	9:  sha1HashAllZero,
	10: "e434f7f779eea9869380bea9f5f4ed75b079c82a",
	11: sha1HashAllZero,
	12: sha1HashAllZero,
	13: sha1HashAllZero,
	14: sha1HashAllZero,
	15: sha1HashAllZero,
	16: sha1HashAllZero,
	17: sha1HashAllFF,
	18: sha1HashAllFF,
	19: sha1HashAllFF,
	20: sha1HashAllFF,
	21: sha1HashAllFF,
	22: sha1HashAllFF,
	23: sha1HashAllZero,
}

var testExpectedPCRsIMANGSha256 = map[int]string{
	0:  "2657c7d8cd7b94d4e702ff4b98dc712578b4eccce3661372a347ef200ae0ff9e",
	1:  sha256HashAllZero,
	2:  sha256HashAllZero,
	3:  sha256HashAllZero,
	4:  sha256HashAllZero,
	5:  sha256HashAllZero,
	6:  sha256HashAllZero,
	7:  "697aa96bb070c35ff75d1f773b7010e87a76494ca1adcf379f1d433105fa0b6b",
	8:  sha256HashAllZero,
	9:  sha256HashAllZero,
	10: "9d7f5614ab14f6dbc6ee694084b05a3c37ede74993eb64f8a74471bbf94368e1",
	11: sha256HashAllZero,
	12: sha256HashAllZero,
	13: sha256HashAllZero,
	14: sha256HashAllZero,
	15: sha256HashAllZero,
	16: sha256HashAllZero,
	17: sha256HashAllFF,
	18: sha256HashAllFF,
	19: sha256HashAllFF,
	20: sha256HashAllFF,
	21: sha256HashAllFF,
	22: sha256HashAllFF,
	23: sha256HashAllZero,
}

func TestPreparePCRsTest(t *testing.T) {
	test.CreateClientConfigFile()
	config.GetDefault(config.ConfClient)
	defer test.RemoveConfigFile()

	cases := []struct {
		imaManifest  []byte
		biosManifest []byte
		hashAlg      string
		expectedPCRs map[int]string
	}{
		{
			imaManifest:  []byte(testIMAManifestIMA),
			biosManifest: testBiosManifest,
			hashAlg:      algSha1Str,
			expectedPCRs: testExpectedPCRsIMA,
		},
		{
			imaManifest:  []byte(testIMAManifestIMANGSha1),
			biosManifest: testBiosManifest,
			hashAlg:      algSha1Str,
			expectedPCRs: testExpectedPCRsIMANGSha1,
		},
		{
			imaManifest:  []byte(testIMAManifestIMANGSha256),
			biosManifest: testBiosManifest,
			hashAlg:      algSha256Str,
			expectedPCRs: testExpectedPCRsIMANGSha256,
		},
	}
	tpmConf := TPMConfig{
		IMALogPath:    TestImaLogPath,
		BIOSLogPath:   TestBiosLogPath,
		ReportHashAlg: "",
	}
	tpm, err := OpenTPM(false, &tpmConf)
	if err != nil {
		t.Errorf("OpenTpm failed, err: %v", err)
		return
	}
	defer tpm.Close()

	for _, c := range cases {
		prepareManifestFiles(TestImaLogPath, TestBiosLogPath, c.imaManifest, c.biosManifest)
		defer removeManifestFiles(TestImaLogPath, TestBiosLogPath)

		tpm.SetDigestAlg(c.hashAlg)
		tpm.dev.(*simulator.Simulator).Reset()

		err = tpm.PreparePCRsTest()
		if err != nil {
			t.Errorf("prepare PCRs failed, err: %v", err)
			return
		}
		pcrs, err := tpm.readPcrs(pcrSelectionAll)
		if err != nil {
			t.Errorf("read PCRs failed, err: %v", err)
		}
		err = comparePCRs(pcrs, c.expectedPCRs)
		if err != nil {
			t.Errorf("prepared PCRs don't meet expectation, err: %v", err)
		}
	}

}

func TestOpenTPM(t *testing.T) {
	tpmConf := TPMConfig{
		IMALogPath:    TestImaLogPath,
		BIOSLogPath:   TestBiosLogPath,
		ReportHashAlg: "",
	}
	_, err := OpenTPM(false, nil)
	if err != errWrongParams {
		t.Errorf("OpenTpm with nil tpmconfig, return unexpected err: %v", err)
	}
	_, err = OpenTPM(false, &tpmConf)
	if err != nil {
		t.Errorf("OpenTpm failed, err: %v", err)
	}
	tpm, err := OpenTPM(false, &tpmConf)
	if err != nil {
		t.Errorf("OpenTpm multiple times failed, err: %v", err)
	}
	sim := tpm.dev
	_, err = openTpmSimulator(tpm)
	if err != errFailTPMInit {
		t.Errorf("OpenTpmSimulator multiple times get unexpected error, err: %v", err)
	}
	tpmRef.dev = sim
	tpmRef.Close()

	tpm, err = OpenTPM(true, &tpmConf)
	if err != errFailTPMInit {
		t.Errorf("OpenTpm open physical tpm get unexpected err: %v", err)
		return
	}
	tpm.Close()
}

func TestGenerateEKey(t *testing.T) {
	test.CreateClientConfigFile()
	config.GetDefault(config.ConfClient)
	defer test.RemoveConfigFile()

	tpmConf := TPMConfig{
		IMALogPath:    TestImaLogPath,
		BIOSLogPath:   TestBiosLogPath,
		ReportHashAlg: "",
	}
	tpm, err := OpenTPM(false, &tpmConf)
	if err != nil {
		t.Errorf("OpenTpm failed, err: %v", err)
	}
	defer tpm.Close()

	tpm.dev.(*simulator.Simulator).Reset()
	i := 0
	for ; i < 100; i++ {
		err = tpm.GenerateEKey()

		if err != nil && i == 0 {
			t.Errorf("GenerateEKey failed to generete EK at the first time: %v", err)
			break
		}
		if err != nil {
			t.Logf("GenerateEKey failed to generete EK at the %d th generation try: %v", i, err)
			break
		}
	}
	if i == 100 {
		t.Errorf("GenerateEKey generated 100 EK without error, unexpected")
	}
}
