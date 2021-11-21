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
	"net"
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

//GetIkCert
func GetIkCert(ekCert string, ikPub string, ikName []byte) (*ToICandSymKey, error) {
	//get decode cert
	root, err := DecodeCert(RootPEM)
	if err != nil {
		return &ToICandSymKey{}, err
	}
	cert, err := DecodeCert(ekCert)
	if err != nil {
		return &ToICandSymKey{}, err
	}
	fmt.Println(cert.Version)
	//verify the ekcert
	ok, err := verifyPCACert(root, cert)
	if !ok {
		return &ToICandSymKey{}, err
	}
	//get decode pubkey
	pub, err := DecodePubkey(ikPub)
	if err != nil {
		return &ToICandSymKey{}, err
	}
	req := Request{
		TPMVer: "2.0",
		IkPub:  nil,
		IkName: ikName,
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		req.IkPub = pub
	default:
		return &ToICandSymKey{}, errors.New("unknown type public key")
	}
	//Examine the Public key
	ok = ExamineIkPub(pub)
	if !ok {
		return &ToICandSymKey{}, errors.New("failed the examine the ikpub")
	}
	//Generate the Credential(is the IkCert)

	return &ToICandSymKey{}, nil

}

// The certificate is signed by parent. If parent is equal to template then the
// certificate is self-signed. The parameter pub is the public key of the
// signee and priv is the private key of the signer.
func GenerateCert(template, parent *x509.Certificate, pub *rsa.PublicKey, priv *rsa.PrivateKey) (*x509.Certificate, []byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, nil, errors.New("Failed to create certificate: " + err.Error())
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, errors.New("Failed to parse certificate: " + err.Error())
	}
	block := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	certPem := pem.EncodeToMemory(&block)
	return cert, certPem, nil
}

//return a root CA and its privateKey
func GenerateRootCA() (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	var rootTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"China"},
			Organization: []string{"Commpany"},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	rootCert, rootPEM, err := GenerateCert(&rootTemplate, &rootTemplate, &priv.PublicKey, priv)
	return rootCert, rootPEM, priv, nil
}
func GeneratePCACert(RootCert *x509.Certificate, Rootkey *rsa.PrivateKey) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	PCAtemplate := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(time.Now().UnixNano()),
		Subject: pkix.Name{
			Country:      []string{"China"},
			Organization: []string{"Company"},
			CommonName:   "privacy ca",
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	pcaCert, pcaPem, err := GenerateCert(&PCAtemplate, RootCert, &priv.PublicKey, Rootkey)
	return pcaCert, pcaPem, priv, nil
}

//pca's private key and the ikPub are the input
//通过pca的私钥作为签名，颁发Ak证书即生成AC
func GenerateIkCert(privacycaCert *x509.Certificate, privacycaKey *rsa.PrivateKey, IkPub *rsa.PublicKey) (*x509.Certificate, []byte, error) {

	template := x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now().Add(-10 * time.Second),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:           false,
		MaxPathLenZero: true,
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
	}
	ikCert, ikPem, err := GenerateCert(&template, privacycaCert, IkPub, privacycaKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate IkCert")
	}

	return ikCert, ikPem, err
}

//Examine  IkPub
func ExamineIkPub(pub crypto.PublicKey) bool {

	return true
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
func DecodePrivkey(pemPrivKey string) (crypto.PrivateKey, error) {
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

//verify the pca Cert by root cert pool
func verifyPCACert(root, cert *x509.Certificate) (bool, error) {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		return false, err
	}
	return true, nil
}
func VerifyIkCert(root, parentCert string, child *x509.Certificate) (bool, error) {
	rootCert, err := DecodeCert(root)
	if err != nil {
		return false, errors.New("failed to decode the root")
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	pCert, err := DecodeCert(parentCert)
	if err != nil {
		return false, errors.New("failed to decode the parent cert")
	}
	inter := x509.NewCertPool()
	inter.AddCert(pCert)
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
	}
	if _, err = child.Verify(opts); err != nil {
		return false, errors.New("failed to verify the child cert")
	}
	return true, nil
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

func getKeybyKDFa(rw io.ReadWriter) ([]byte, error) {

	//get the seed
	seed, err := tpm2.GetRandom(rw, 16)
	if err != nil {
		return nil, errors.Errorf("failed get seed from TPM")
	}
	contextU := []byte{'k', 'e', 'k', 0}
	contextV := []byte{'y', 'o', 'y', 'o', 0}
	key, err := tpm2.KDFa(tpm2.AlgSHA256, seed, "IDENTITY", contextU, contextV, 128)
	if err != nil {
		return nil, errors.Errorf("failed create key from KDFa")
	}

	return key, nil
}

//加密ac
func EncryptIkcert(IkCert []byte, IkName []byte) (ToICandSymKey, error) {
	//对传进来的IkCert进行加密，使用symKey作为加密密钥
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
	encryptIC, err := SymetricEncrypt(IkCert, Secret, iv, TPM_AES, TPM_CBC)

	if err != nil {
		errors.New("failed the SymetricEncrypt")
	}
	parentHandle, _, err := tpm2.CreatePrimary(simulator, tpm2.HandleOwner, PcrSelection, ParentPassword, DefaultPassword, DefaultKeyParams)
	if err != nil {
		errors.New("failed CreatePrimary")
	}
	//generate the credential
	credentialSecret, credentialBlob, err := tpm2.MakeCredential(simulator, parentHandle, Secret, IkName)
	if err != nil {
		errors.New("failed the MakeCredential")
	}
	//encrypt the Secret by symkey from KDFa
	key, err := getKeybyKDFa(simulator)
	if err != nil {
		errors.New("failed get key from KDFa")
	}
	encryptSecret, err := SymetricEncrypt(Secret, key, iv, TPM_AES, TPM_CBC) //先用空值和上面生成作为初步过程
	if err != nil {
		errors.New("failed encrypt the Secret")
	}
	symKeyParams := TPMSymKeyParams{
		EncryptIC:     encryptIC,
		EncryptSecret: encryptSecret,
		IV:            iv,
	}
	toACandsymKey := ToICandSymKey{
		Credential:      credentialSecret,
		SymBlob:         credentialBlob,
		TPMSymKeyParams: symKeyParams,
	}

	return toACandsymKey, nil
}
func Test() {
	fmt.Println("hello, this is pca!")
}
