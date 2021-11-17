package pca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/pkg/errors"
)

const (
	TPM_AES = "AES"
	TPM_CBC = "CBC"
)

type PCA struct {
}
type PrivacyCA interface {
}

//Decode the cert from pem cert
func DecodeCert(pemCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, errors.New("failed to Decode the cert pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse public key : " + err.Error())
	}
	return cert, nil
}

//Decode the publicKey from pem PubKey
func DecodePubkey(pemPubKey string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemPubKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse public key : " + err.Error())
	}
	return pub, nil
}

//Decode the privateKey from pem PrivKey
func DecodePrivkey(pemPrivKey string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemPrivKey))
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	return nil, nil
}

//生成一个新的pca接口
func NewPCA(req Request) (PrivacyCA, error) {
	if req.TPMVer == "2.0" {
		return &PCA{}, nil
	}
	return nil, errors.New("NewPCA() Is a unsupported TPM")
}

//验证ek证书
func VerifyEkCert(EkCert *x509.Certificate) bool {
	//验证Ek证书签名的认证
	//1. Create the set of root certificates
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(RootPEM))
	if !ok {
		errors.New("failed to parse root certificate")
		return false
	}
	//2. verify the ekcert by the root certificate
	cert, _ := DecodeCert(CertPEM)
	opts := x509.VerifyOptions{
		DNSName: "mail.google.com",
		Roots:   roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		errors.New("failed to verify certificate")
		return false
	}

	return true
}

//通过pca的私钥作为签名，颁发Ak证书即生成AC
func GenerateAkCert(privacycaKey crypto.PrivateKey, privacycaCert *x509.Certificate, AkPub rsa.PublicKey) ([]byte, error) {
	//还未确定明白Templte中应该包含哪些
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		errors.New("create the serialNumber failed")
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(8760 * time.Hour)
	template := x509.Certificate{
		Version:      2.0,
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{}, //there is a question
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	} //通过x509.CreateCertificate()生成Akcert
	AkCert, err := x509.CreateCertificate(rand.Reader, &template, privacycaCert, AkPub, privacycaKey)
	if err != nil {
		return nil, errors.Wrap(err, "while generate AkCert is error")
	}

	return AkCert, err
}
func GetSignatureALG(pubKey crypto.PublicKey) (x509.SignatureAlgorithm, error) {
	switch pubKey.(type) {
	case *rsa.PublicKey:
		return x509.SHA384WithRSA, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("there is a unknown pubKey type")
	}
}

type IdentityResponse struct {
}

func getKeybyKDFa(rw io.ReadWriter) ([]byte, []byte, error) {

	//get the seed
	seed, err := tpm2.GetRandom(rw, 16)
	if err != nil {
		return nil, nil, errors.Errorf("failed get seed from TPM")
	}
	contextU := []byte{'k', 'e', 'k', 0}
	contextV := []byte{'y', 'o', 'y', 'o', 0}
	key, err := tpm2.KDFa(tpm2.AlgSHA256, seed, "IDENTITY", contextU, contextV, 128)
	if err != nil {
		return nil, nil, errors.Errorf("failed create key from KDFa")
	}

	return key, nil, nil
}

//加密ac
func EncryptAkcert(AkCert []byte, AkName []byte) (ToACandSymKey, error) {
	//对传进来的akCert进行加密，使用symKey作为加密密钥
	Secret, err := CreateRandomByte(16)
	if err != nil {
		errors.New("failed create the symkey of a random byte")
	}
	simulator, err := simulator.Get()
	if err != nil {
		errors.New("failed get the simulator")
	}

	iv, err := CreateRandomByte(16)
	if err != nil {
		errors.New("failed create the iv of a random byte")
	}
	encryptAC, err := SymetricEncrypt(AkCert, Secret, iv, TPM_AES, TPM_CBC)

	if err != nil {
		errors.New("failed the SymetricEncrypt")
	}
	parentHandle, _, err := tpm2.CreatePrimary(simulator, tpm2.HandleOwner, PcrSelection, ParentPassword, DefaultPassword, DefaultKeyParams)
	if err != nil {
		errors.New("failed CreatePrimary")
	}
	//generate the credential
	credentialSecret, credentialBlob, err := tpm2.MakeCredential(simulator, parentHandle, Secret, AkName)
	if err != nil {
		errors.New("failed the MakeCredential")
	}
	//encrypt the Secret by symkey from KDFa
	key, encryptSeed, err := getKeybyKDFa(simulator)
	if err != nil {
		errors.New("failed get key from KDFa")
	}
	encryptSecret, err := SymetricEncrypt(Secret, key, iv, TPM_AES, TPM_CBC) //先用空值和上面生成作为初步过程
	if err != nil {
		errors.New("failed encrypt the Secret")
	}
	symKeyParams := TPMSymKeyParams{
		EncryptAC:     encryptAC,
		EncryptSeed:   encryptSeed,
		EncryptSecret: encryptSecret,
		IV:            iv,
	}
	toACandsymKey := ToACandSymKey{
		Credential:      credentialSecret,
		SymBlob:         credentialBlob,
		TPMSymKeyParams: symKeyParams,
	}

	return toACandsymKey, nil
}
func Test() {
	fmt.Println("hello, this is pca!")
}
