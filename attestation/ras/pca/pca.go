package pca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/pkg/errors"
)

const (
	TPM_AES     = "AES"
	TPM_CBC     = "CBC"
	Encrypt_Alg = "AES128-CBC"
)

var caIP = "127.0.0.1"

type PCA struct {
}
type PrivacyCA interface {
}

//GetIkCert
func GetIkCert(ekCert string, ikPub string, ikName []byte) (*IKCertChallenge, error) {
	//get decode cert
	root, err := DecodeCert(CertPEM)
	if err != nil {
		return nil, err
	}
	cert, err := DecodeCert(ekCert)
	if err != nil {
		return nil, err
	}
	fmt.Println(cert.Version)
	//verify the ekcert
	ok, err := verifyPCACert(root, cert)
	if !ok {
		return nil, err
	}
	//get decode pubkey
	pub, err := DecodePubkey(ikPub)
	if err != nil {
		return nil, err
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
		return nil, errors.New("unknown type public key")
	}
	//Generate the Credential(is the IkCert)
	pcaCert, err := DecodeCert(CertPEM)
	if err != nil {
		return nil, errors.New("Failed to decode the pca Cert")
	}
	pcaPriv, err := DecodePrivkey(PrivPEM)
	if err != nil {
		return nil, errors.New("Failed to decode the private key")
	}
	_, ikPerm, err := GenerateIkCert(pcaCert, pcaPriv, req.IkPub)
	if err != nil {
		return nil, errors.New("Failed to generate the ikCert")
	}

	// encrypt the Credential
	return EncryptIkcert(cert.PublicKey, ikPerm, ikName)
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
func GenerateCertToFile(template, parent *x509.Certificate, pub *rsa.PublicKey, priv *rsa.PrivateKey, fileName string) (*x509.Certificate, []byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, nil, errors.New("Failed to create certificate: " + err.Error())
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, errors.New("Failed to parse certificate: " + err.Error())
	}
	err = EncodeCert(certBytes, fileName)
	if err != nil {
		return nil, nil, err
	}
	block := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	certPem := pem.EncodeToMemory(&block)
	return cert, certPem, nil
}

//Encode cert
//name is the encode name
func EncodeCert(certBytes []byte, name string) error {
	crt, err := os.Create(name)
	if err != nil {
		return err
	}
	pem.Encode(crt, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	crt.Close()
	return nil
}
func DecodeCertFromFile(fileName string) (*x509.Certificate, error) {
	f, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return DecodeCert(string(f))
}
func EncodePrivToFile(priv *rsa.PrivateKey, name string) error {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(priv)
	p, err := os.Create(name)
	if err != nil {
		return err
	}
	pem.Encode(p, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privKeyBytes})
	p.Close()
	return nil
}
func DecodePrivFromFile(fileName string) (*rsa.PrivateKey, error) {
	f, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return DecodePrivkey(string(f))
}

//return a root CA and its privateKey
func GenerateRootCA() (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	rootTemplate := x509.Certificate{
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
		IPAddresses:           []net.IP{net.ParseIP(caIP)},
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	err = EncodePrivToFile(priv, "rootPriv.pem")
	if err != nil {
		return nil, nil, nil, err
	}
	rootCert, rootPEM, err := GenerateCertToFile(&rootTemplate, &rootTemplate, &priv.PublicKey, priv, "root.crt")
	return rootCert, rootPEM, priv, err
}
func GeneratePCACert(RootCert *x509.Certificate, Rootkey *rsa.PrivateKey) (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	err = EncodePrivToFile(priv, "pcaPriv.pem")
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
		IPAddresses:           []net.IP{net.ParseIP(caIP)},
	}
	pcaCert, pcaPem, err := GenerateCertToFile(&PCAtemplate, RootCert, &priv.PublicKey, Rootkey, "pca.crt")
	return pcaCert, pcaPem, priv, err
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
		//		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
	}
	ikCert, ikPem, err := GenerateCert(&template, privacycaCert, IkPub, privacycaKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate IkCert")
	}

	return ikCert, ikPem, err
}

//自签名
//template = parent
//name is the os.Create's name : "RootCert.crt"
func GenerateCertbyOneself(privKey *rsa.PrivateKey, publicKey *rsa.PublicKey, name string) (*x509.Certificate, []byte, error) {
	template := x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now().Add(-10 * time.Second),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:           true,
		MaxPathLenZero: true,
		//		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
	}
	Cert, Pem, err := GenerateCert(&template, &template, publicKey, privKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate Cert")
	}
	crt, err := os.Create(name)
	if err != nil {
		return nil, nil, err
	}
	pem.Encode(crt, &pem.Block{Type: "CERTIFICATE", Bytes: Pem})
	crt.Close()
	return Cert, Pem, err
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
func DecodePrivkey(pemPrivKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemPrivKey))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("Failed to parse the private key")
	}
	return priv, nil
}

//Generate a rsa key by rsa.generatekey
func GenerateRsaKey() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, errors.New("Failed to generate the RSA key")
	}
	return privKey, &privKey.PublicKey, nil
}

//Encode the rsa key
func EncodePrivKeyAsPemStr(priv *rsa.PrivateKey) (string, error) {
	privByte := x509.MarshalPKCS1PrivateKey(priv)
	privPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privByte,
		},
	)
	return string(privPem), nil
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

//Generate a signature by private key
func GenerateSignature(data []byte) ([]byte, [32]byte, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("Failed to generate a key")
	}
	pub := &priv.PublicKey
	digest := sha256.Sum256(data)
	//generate the signature by priv key
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		panic("Failed to get a signature")
	}
	return signature, digest, pub, err
}

//Verify a signature by a public key and examine the pub meanwhile
func VerifySigAndPub(signature []byte, hash [32]byte, pub *rsa.PublicKey) error {
	err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], signature)
	if err != nil {
		return errors.New("failed the verify pub")
	}
	return err
}

type IdentityResponse struct {
}

func GetKeybyKDFa(rw io.ReadWriter) ([]byte, error) {

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

func pubKeyToTPMPublic(ekPubKey crypto.PublicKey) *tpm2.Public {
	pub := DefaultKeyParams
	pub.RSAParameters.KeyBits = uint16(uint32(ekPubKey.(*rsa.PublicKey).N.BitLen()))
	pub.RSAParameters.ExponentRaw = uint32(ekPubKey.(*rsa.PublicKey).E)
	pub.RSAParameters.ModulusRaw = ekPubKey.(*rsa.PublicKey).N.Bytes()

	return &pub
}

var (
	simulatorMutex sync.Mutex
)

//加密ac
func EncryptIkcert(ekPubKey crypto.PublicKey, IkCert []byte, IkName []byte) (*IKCertChallenge, error) {
	//对传进来的IkCert进行加密，使用symKey作为加密密钥
	Secret, err := CreateRandomBytes(16)
	if err != nil {
		return nil, errors.New("failed create the symkey of a random byte")
	}
	iv, err := CreateRandomBytes(16)
	if err != nil {
		return nil, errors.New("failed create the iv of a random byte")
	}
	encryptedCert, err := SymetricEncrypt(IkCert, Secret, iv, TPM_AES, TPM_CBC)

	if err != nil {
		return nil, errors.New("failed the SymetricEncrypt")
	}

	ekPub := pubKeyToTPMPublic(ekPubKey)

	simulatorMutex.Lock()
	defer simulatorMutex.Unlock()

	simulator, err := simulator.Get()
	if err != nil {
		return nil, errors.New("failed get the simulator")
	}
	defer simulator.Close()

	protectHandle, _, err := tpm2.LoadExternal(simulator, *ekPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		log.Println(err)
		return nil, errors.New("failed load ekPub")
	}

	//generate the credential
	credBlob, encryptedSecret, err := tpm2.MakeCredential(simulator, protectHandle, Secret, IkName)
	if err != nil {
		return nil, errors.New("failed the MakeCredential")
	}

	symKeyParams := TPMSymKeyParams{
		CredBlob:        credBlob,        //前两个参数是makecredential的返回值，通过使用activateCredential
		EncryptedSecret: encryptedSecret, //可以解出secret
		EncryptAlg:      Encrypt_Alg,
		EncryptParam:    iv, //iv  + 上面解出的secret可以解密出ikcret
	}
	ikCertChallenge := IKCertChallenge{
		EncryptedCert:   encryptedCert, //存放加密后的ikCert
		TPMSymKeyParams: symKeyParams,
	}

	return &ikCertChallenge, nil
}

// Generate an ek certificate based on the ek public key, and return the .der format of the certificate
// The certificate is signed by PCA.
func GenerateEKCert(ekPub *rsa.PublicKey) ([]byte, error) {
	template := x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now().Add(-10 * time.Second),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:           false,
		MaxPathLenZero: true,
		IPAddresses:    []net.IP{net.ParseIP(caIP)},
	}
	pcaCert, err := DecodeCert(CertPEM)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode cert while generate EKCert")
	}
	pcaPriv, err := DecodePrivkey(PrivPEM)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode key while generate EKCert")
	}

	ekCertDer, err := x509.CreateCertificate(rand.Reader, &template, pcaCert, ekPub, pcaPriv)
	if err != nil {
		return nil, errors.New("Failed to create certificate: " + err.Error())
	}

	if err != nil {
		return nil, errors.Wrap(err, "failed to generate EKCert")
	}
	return ekCertDer, err
}
