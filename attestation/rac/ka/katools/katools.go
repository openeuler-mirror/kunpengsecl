package main

/*
#cgo CFLAGS: -I../ktalib -I../teesimulator
#cgo LDFLAGS: -L${SRCDIR}/../ktalib -lkta -Wl,-rpath=${SRCDIR}/../ktalib -lkta -ldl
#include "ktalib.h"

*/
/*
//#cgo CFLAGS: -I../ktalib -I../ktalib/itrustee_sdk/include/CA
//#cgo LDFLAGS: -L${SRCDIR}/../ktalib -lkta -Wl,-rpath=${SRCDIR}/../ktalib -lkta -ldl
//#include "ktalib.h"

*/
import "C"
import (
	"crypto/x509"
	"fmt"
	"unsafe"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
)

const (
	RSA_PUBLIC_SZIE  = 4096
	CERTIFICATE_SIZE = 3024
)

/*
   初始化KTA阶段主要分为以下几个过程
   1.ka向KCM发起请求获取KCM公钥证书
       GetKCMCert()certificate
   2.验证KCM证书
   3.对KTA进行初始化，传递KCM公钥
   4.KTA侧返回KTA公钥证书
   5.KA向KCM传递设备ID、KTA公钥证书
*/
/*
using the cert of kcm to initialize the kta
will get the kta cert by byte array and error
*/
func InitialKTA(cert *x509.Certificate) ([]byte, error) {
	//verify the cert of kcm
	err := verifyCert("./test.crt", cert)
	if err != nil {
		return []byte{}, err
	}
	pub := cert.PublicKey
	pubKey, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return []byte{}, err
	}
	pub_buf := C.CBytes(pubKey)
	c_request_data := C.struct_buffer_data{
		C.__uint32_t(len(pubKey)), (*C.uchar)(pub_buf)}
	c_response_data := C.struct_buffer_data{}
	cmd := C.uint(1)
	c_response_data.size = C.uint(CERTIFICATE_SIZE)
	c_response_data.buf = (*C.uint8_t)(C.malloc(C.ulong(c_response_data.size)))

	C.RemoteAttestKTA(cmd, &c_request_data, &c_response_data)
	testByte := []byte(C.GoBytes(unsafe.Pointer(c_response_data.buf), C.int(c_response_data.size)))
	fmt.Println(string(testByte))
	fmt.Println(c_response_data.size)
	return []byte{}, nil
}

func verifyCert(s string, cert *x509.Certificate) error {
	return nil
}

// func InitialKTA() {
// 	//测试KTA的初始化过程
// 	c_request_data := C.struct_buffer_data{}
// 	c_response_data := C.struct_buffer_data{}
// 	cmd := C.uint(1)

// 	C.RemoteAttestKTA(cmd, &c_request_data, &c_response_data)
// 	testByte := []byte(C.GoBytes(unsafe.Pointer(c_response_data.buf), C.int(c_response_data.size)))
// 	fmt.Println(string(testByte))
// }
func main() {
	cert, _, err := cryptotools.DecodeKeyCertFromFile("./test.crt")
	if err != nil {
		fmt.Println("failed")
		return
	}
	_, err = InitialKTA(cert)
	fmt.Println(err)
	//InitialKTA()
}
