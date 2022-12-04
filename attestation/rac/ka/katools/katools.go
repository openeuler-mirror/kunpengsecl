package katools

/*
#cgo CFLAGS: -I../ktalib -I../ktalib/itrustee_sdk/include/CA
#cgo LDFLAGS: -L${SRCDIR}/../ktalib -lkta -Wl,-rpath=${SRCDIR}/../ktalib -lkta -ldl
#include "ktalib.h"

*/
/*
//#cgo CFLAGS: -I../ktalib -I../teesimulator
//#cgo LDFLAGS: -L${SRCDIR}/../ktalib -lkta -Wl,-rpath=${SRCDIR}/../ktalib -lkta -ldl
//#include "ktalib.h"

*/
import "C"
import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"time"
	"unsafe"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
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
// func main() {
// 	cert, _, err := cryptotools.DecodeKeyCertFromFile("../cert/kta.crt")
// 	if err != nil {
// 		fmt.Println("failed")
// 		return
// 	}
// 	_, err = InitialKTA(cert)
// 	fmt.Println(err)
// 	//InitialKTA()
// }

// KA主函数
func KaMain(addr string, id int64) {
	c_context := C.TEEC_Context{}
	c_session := C.TEEC_Session{}
	err := getContextSession(&c_context, &c_session)
	if err != nil {
		fmt.Printf("open session failed\n")
	}
	defer C.KTAshutdown(&c_context, &c_session)
	ras, err := clientapi.CreateConn(addr)
	defer clientapi.ReleaseConn(ras)
	if err != nil {
		logger.L.Sugar().Errorf("connect ras server fail, %s", err)
	}
	// 从clientapi获得公钥证书
	kcm_cert_data, err := clientapi.DoSendKCMPubKeyCertWithConn(ras, &clientapi.SendKCMPubKeyCertRequest{})
	// kcm_cert_data, err := ioutil.ReadFile("../../../ras/kcms/cert/kcm.crt")
	if err != nil || !kcm_cert_data.Result {
		fmt.Printf("get kcm cert error\n")
	}
	kcm_cert, _, err := cryptotools.DecodeKeyCertFromPEM(kcm_cert_data.KcmPubKeyCert)
	if err != nil {
		fmt.Printf("get kcm cert error\n")
	}
	// 验证公钥证书
	ca_cert, _, err := cryptotools.DecodeKeyCertFromFile("../../ka/cert/ca.crt")
	if err != nil {
		fmt.Printf("get ca cert error\n")
	}
	err1 := validateCert(kcm_cert, ca_cert)
	if err1 != nil {
		fmt.Printf("cert error\n")
	} else {
		fmt.Printf("cert successfull\n")
	}
	// kta公钥
	pub1 := kcm_cert.PublicKey
	kcmPubkey, err := x509.MarshalPKIXPublicKey(pub1)
	if err != nil {
		fmt.Printf("get kcmPubkey error\n")
	}
	// kta私钥
	keypemData, _ := ioutil.ReadFile("../../ka/cert/kta.key")
	block, _ := pem.Decode(keypemData)
	ktaPrivKey := block.Bytes
	// kta公钥证书
	ktaPubCert, err := ioutil.ReadFile("../../ka/cert/kta.crt")
	if err != nil {
		fmt.Printf("get ktaPubCert error\n")
	}

	ktaCert, err := initialKTA(&c_session, kcmPubkey, ktaPrivKey, ktaPubCert)
	if err != nil {
		logger.L.Sugar().Errorf("init kta fail, %s", err)
	}
	req := clientapi.VerifyKTAPubKeyCertRequest{
		ClientId:      id,
		KtaPubKeyCert: ktaCert,
	}
	//向clientapi发送证书和设备id
	rpy, err := clientapi.DoVerifyKTAPubKeyCertWithConn(ras, &req)
	if err != nil || !rpy.Result {
		fmt.Printf("Verify KTA PubKeyCert error\n")
	}
	// 删除密钥文件
	// os.Remove("../../ka/cert/kta.key")
	// os.Remove("../../ka/cert/kta.crt")

	// 轮询密钥请求过程
	kaLoop(ras, &c_session, 1*time.Second)

}

// 轮询函数
func kaLoop(ras *clientapi.RasConn, c_session *C.TEEC_Session, askDuration time.Duration) {
	for {
		nextCmd, err := getKTACmd(c_session)
		if err != nil {
			fmt.Printf("get KTACmd error\n")
		}
		req := clientapi.KeyOperationRequest{
			EncMessage: nextCmd,
		}
		// 向clientapi返回
		rpy, err := clientapi.DoKeyOperationWithConn(ras, &req)
		if err != nil {
			fmt.Printf("Do KeyOperation WithConn error\n")
		}
		err1 := sendRpyToKTA(c_session, rpy.EncRetMessage)
		if err1 != nil {
			fmt.Printf("send Rpy To KTA error\n")
		}
		// 错误处理

		time.Sleep(askDuration)

	}
}

// 建立上下文和会话
func getContextSession(c_context *C.TEEC_Context, c_session *C.TEEC_Session) error {
	teec_result := C.InitContextSession(c_context, c_session)
	if int(teec_result) != 0 {
		return errors.New("get session failed")
	}
	return nil
}

//初始化KTA
func initialKTA(c_session *C.TEEC_Session, kcmPubkey []byte, ktaPrivKey []byte, ktaPubCert []byte) ([]byte, error) {

	c_kcmPubkey := C.CBytes(kcmPubkey)
	defer C.free(c_kcmPubkey)
	c_request_data1 := C.struct_buffer_data{
		C.__uint32_t(len(kcmPubkey)), (*C.uchar)(c_kcmPubkey)}
	c_ktaPrivKey := C.CBytes(ktaPrivKey)
	defer C.free(c_ktaPrivKey)
	c_request_data2 := C.struct_buffer_data{
		C.__uint32_t(len(ktaPrivKey)), (*C.uchar)(c_ktaPrivKey)}
	c_ktaPubCert := C.CBytes(ktaPubCert)
	defer C.free(c_ktaPubCert)
	c_request_data3 := C.struct_buffer_data{
		C.__uint32_t(len(ktaPubCert)), (*C.uchar)(c_ktaPubCert)}
	// 返回值
	c_response_data := C.struct_buffer_data{}
	c_response_data.size = C.__uint32_t(len(ktaPubCert))
	c_response_data.buf = (*C.uint8_t)(C.malloc(C.ulong(c_response_data.size)))
	teec_result := C.KTAinitialize(c_session, &c_request_data1, &c_request_data2, &c_request_data3, &c_response_data)
	if int(teec_result) != 0 {
		return nil, errors.New("initial kta failed")
	}
	bk := C.GoBytes(unsafe.Pointer(c_response_data.buf), C.int(c_response_data.size))

	return bk, nil
}

// 从KTA拿取密钥请求
func getKTACmd(c_session *C.TEEC_Session) ([]byte, error) {
	c_cmd_data := C.struct_buffer_data{}
	// malloc大小待设置
	c_cmd_data.size = C.__uint32_t(10000)
	c_cmd_data.buf = (*C.uint8_t)(C.malloc(C.ulong(c_cmd_data.size)))
	teec_result := C.KTAgetCommand(c_session, &c_cmd_data)
	if int(teec_result) != 0 {
		return nil, errors.New("get kta commmand failed")
	}
	bk := C.GoBytes(unsafe.Pointer(c_cmd_data.buf), C.int(c_cmd_data.size))

	return bk, nil
}

// 向KTA返发送密钥请求返回值
func sendRpyToKTA(c_session *C.TEEC_Session, rpy []byte) error {
	c_cmd_data := C.CBytes(rpy)
	defer C.free(c_cmd_data)
	c_request_data := C.struct_buffer_data{
		C.__uint32_t(len(rpy)), (*C.uchar)(c_cmd_data)}
	teec_result := C.KTAsendCommandreply(c_session, &c_request_data)
	if int(teec_result) != 0 {
		return errors.New("send kta commmand rpy failed")
	}

	return nil
}

// 证书验证
func validateCert(cert, parent *x509.Certificate) error {
	//check the period validate
	timeNow := time.Now()
	if !timeNow.Before(parent.NotAfter) {
		return errors.New("the certificate has expired")
	}
	// er := cert.CheckSignatureFrom(parent)
	// if er == nil {
	// 	fmt.Println("success")
	// 	return er
	// }
	if cert.Issuer.CommonName != parent.Subject.CommonName {
		return errors.New("cert issuer name is not the parent subject name")
	}
	err := parent.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return err
	}
	return nil
}
