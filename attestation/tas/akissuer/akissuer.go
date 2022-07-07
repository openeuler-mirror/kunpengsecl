/***
Description: Implement specific services provided by AS
***/

package akissuer

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"

	"gitee.com/openeuler/kunpengsecl/attestation/tas/config"
	"gitee.com/openeuler/kunpengsecl/attestation/tas/database"
)

/***
1.入参为目标平台设备证书颁发的AK证书以及设备证书
2.收到证书后，进行解析
4.使用设备证书对AK证书进行验签，验签通过则信任该证书
5.使用AS密钥对和AS证书对AK证书进行重新签名
6.返回重新签名后的AK证书
***/
func GenerateAKCert(oldAKCert []byte, dvcertbyte []byte) ([]byte, error) { // dvcert -> drkcert
	// parse ak cert signed by device cert
	certBlock, _ := pem.Decode(oldAKCert)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Print("flag")
		return nil, err
	}
	// parse device cert
	dvcertBlock, _ := pem.Decode(dvcertbyte)
	dvcert, err := x509.ParseCertificate(dvcertBlock.Bytes)
	if err != nil {
		return nil, err
	}
	// verify signature
	err = cert.CheckSignatureFrom(dvcert)
	if err != nil {
		return nil, err
	}
	// get as cert and as private key
	ascert := config.GetASCert()
	asprivkey := config.GetASPrivKey()
	// resign ak cert
	newCertDer, err := x509.CreateCertificate(rand.Reader, cert, ascert, ascert.PublicKey, asprivkey)
	if err != nil {
		return nil, err
	}
	newCertBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCertDer,
	}
	newCertPem := pem.EncodeToMemory(newCertBlock)
	d, err := database.InsertDKeyRow(dvcertbyte)
	if err != nil {
		log.Printf("Insert device key row failed, error: %v", err)
	}
	err = database.InsertAKCertRow(newCertPem, d.Id)
	if err != nil {
		log.Printf("Insert AKey Cert row failed, error: %v", err)
	}
	return newCertPem, nil
}

func RegisterClient(info string, cert []byte) (int64, error) {
	d, err := database.RegisterClientByDC(cert, info)
	if err != nil {
		return -1, err
	}
	return d.Id, nil
}
