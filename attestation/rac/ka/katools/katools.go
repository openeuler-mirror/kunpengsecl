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
	"io/ioutil"
	"os"
	"time"
	"unsafe"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
)

const (
	CMD_DATA_SZIE = 4096 // Now set randomly
)

// KA主函数
func KaMain(addr string, id int64) {
	logger.L.Debug("start ka...")
	loadConfigs()
	c_kta_path := C.CString(getKtaPath())
	defer C.free(unsafe.Pointer(c_kta_path))
	err := getContextSession(c_kta_path)
	if err != nil {
		logger.L.Sugar().Errorf("open session failed, %s", err)
		return
	}
	defer C.KTAshutdown()
	ras, err := clientapi.CreateConn(addr)
	if err != nil {
		logger.L.Sugar().Errorf("connect ras server fail, %s", err)
		return
	}
	defer clientapi.ReleaseConn(ras)
	err1 := kaInitialize(ras, id)
	if err1 != nil {
		return
	}
	// 轮询密钥请求过程
	kaLoop(ras, getPollDuration())
	logger.L.Debug("ka closed...")
}
func kaInitialize(ras *clientapi.RasConn, id int64) error {
	// 从clientapi获得公钥证书
	kcm_cert_data, err := clientapi.DoSendKCMPubKeyCertWithConn(ras, &clientapi.SendKCMPubKeyCertRequest{})
	if err != nil || !kcm_cert_data.Result {
		logger.L.Sugar().Errorf("get kcm cert from clientapi error, %s", err)
		return err
	}
	kcm_cert, _, err := cryptotools.DecodeKeyCertFromPEM(kcm_cert_data.KcmPubKeyCert)
	if err != nil {
		logger.L.Sugar().Errorf("decode kcm cert from clientapi error, %s", err)
		return err
	}
	// 验证公钥证书
	ca_cert, _, err := cryptotools.DecodeKeyCertFromFile(getCaCertFile())
	if err != nil {
		logger.L.Sugar().Errorf("decode ca cert from file error, %s", err)
		return err
	}
	err1 := validateCert(kcm_cert, ca_cert)
	if err1 != nil {
		logger.L.Sugar().Errorf("validate kcm cert error, %s", err1)
		return err1
	} else {
		logger.L.Debug("validate kcm cert success")
	}
	kcmPubkey, ktaPubCert, ktaPrivKey, err := getSendKtaData(kcm_cert)
	if err != nil {
		logger.L.Sugar().Errorf("get send kta data fail, %s", err)
		return err
	}
	ktaCert, err := initialKTA(kcmPubkey, ktaPubCert, ktaPrivKey)
	if err != nil {
		logger.L.Sugar().Errorf("init kta fail, %s", err)
		terminateKTA()
		return err
	}
	// 删除密钥文件
	removeKeyFile()
	req := clientapi.VerifyKTAPubKeyCertRequest{
		ClientId:      id,
		KtaPubKeyCert: ktaCert,
	}
	//向clientapi发送证书和设备id
	rpy, err := clientapi.DoVerifyKTAPubKeyCertWithConn(ras, &req)
	if err != nil || !rpy.Result {
		logger.L.Sugar().Errorf("kcm verify kta pubKeycert error, %s", err)
		terminateKTA()
		return err
	}
	logger.L.Debug("ka initialize done")
	return nil
}
func getSendKtaData(kcm_cert *x509.Certificate) ([]byte, []byte, []byte, error) {
	pub1 := kcm_cert.PublicKey
	kcmPubkey, err := x509.MarshalPKIXPublicKey(pub1)
	if err != nil {
		logger.L.Sugar().Errorf("decode kcm pubkey error, %s", err)
		return nil, nil, nil, err
	}
	ktaPubCert, err := ioutil.ReadFile(getKtaCertFile())
	if err != nil {
		logger.L.Sugar().Errorf("read kta pubcert from file error, %s", err)
		return nil, nil, nil, err
	}
	keypemData, err := ioutil.ReadFile(getKtaKeyFile())
	if err != nil {
		logger.L.Sugar().Errorf("read kta privkey from file error, %s", err)
		return nil, nil, nil, err
	}
	block, _ := pem.Decode(keypemData)
	ktaPrivKey := block.Bytes

	return kcmPubkey, ktaPubCert, ktaPrivKey, nil
}
func removeKeyFile() {
	os.Remove(getKtaCertFile())
	os.Remove(getKtaKeyFile())
}

// 轮询函数
func kaLoop(ras *clientapi.RasConn, askDuration time.Duration) {
	logger.L.Debug("start ka loop...")
	for {
		nextCmd, err := getKTACmd()
		if err != nil {
			logger.L.Sugar().Errorf("get kta command error, %s", err)
			break
			// time.Sleep(askDuration)
			// continue
		}
		req := clientapi.KeyOperationRequest{
			EncMessage: nextCmd,
		}
		// 向clientapi返回
		rpy, err := clientapi.DoKeyOperationWithConn(ras, &req)
		if err != nil {
			logger.L.Sugar().Errorf("do key operation withconn error, %s", err)
			break
		}
		err1 := sendRpyToKTA(rpy.EncRetMessage)
		if err1 != nil {
			logger.L.Sugar().Errorf("send rpy to kta error, %s", err)
			break
		}
		time.Sleep(askDuration)
	}
	terminateKTA()
}

// 建立上下文和会话
func getContextSession(c_path *C.char) error {
	c_kta_path := (*C.uchar)(unsafe.Pointer((*C.uchar)(unsafe.Pointer(c_path))))
	teec_result := C.InitContextSession(c_kta_path)
	if int(teec_result) != 0 {
		return errors.New("get session failed")
	}
	return nil
}

//初始化KTA
func initialKTA(kcmPubkey []byte, ktaPubCert []byte, ktaPrivKey []byte) ([]byte, error) {

	c_kcmPubkey := C.CBytes(kcmPubkey)
	defer C.free(c_kcmPubkey)
	c_request_data1 := C.struct_buffer_data{
		C.__uint32_t(len(kcmPubkey)), (*C.uchar)(c_kcmPubkey)}
	c_ktaPubCert := C.CBytes(ktaPubCert)
	defer C.free(c_ktaPubCert)
	c_request_data2 := C.struct_buffer_data{
		C.__uint32_t(len(ktaPubCert)), (*C.uchar)(c_ktaPubCert)}
	c_ktaPrivKey := C.CBytes(ktaPrivKey)
	defer C.free(c_ktaPrivKey)
	c_request_data3 := C.struct_buffer_data{
		C.__uint32_t(len(ktaPrivKey)), (*C.uchar)(c_ktaPrivKey)}

	// 返回值
	c_response_data := C.struct_buffer_data{}
	c_response_data.size = C.__uint32_t(len(ktaPubCert))
	c_response_data.buf = (*C.uint8_t)(C.malloc(C.ulong(c_response_data.size)))
	teec_result := C.KTAinitialize(&c_request_data1, &c_request_data2, &c_request_data3, &c_response_data)
	if int(teec_result) != 0 {
		return nil, errors.New("initial kta failed")
	}
	bk := C.GoBytes(unsafe.Pointer(c_response_data.buf), C.int(c_response_data.size))

	return bk, nil
}

// 从KTA拿取密钥请求
func getKTACmd() ([]byte, error) {
	c_cmd_data := C.struct_buffer_data{}
	// malloc大小待设置
	c_cmd_data.size = C.__uint32_t(CMD_DATA_SZIE)
	c_cmd_data.buf = (*C.uint8_t)(C.malloc(C.ulong(c_cmd_data.size)))
	teec_result := C.KTAgetCommand(&c_cmd_data)
	if int(teec_result) != 0 {
		return nil, errors.New("get kta commmand failed")
	}
	bk := C.GoBytes(unsafe.Pointer(c_cmd_data.buf), C.int(c_cmd_data.size))

	return bk, nil
}

// 向KTA返发送密钥请求返回值
func sendRpyToKTA(rpy []byte) error {
	c_cmd_data := C.CBytes(rpy)
	defer C.free(c_cmd_data)
	c_request_data := C.struct_buffer_data{
		C.__uint32_t(len(rpy)), (*C.uchar)(c_cmd_data)}
	teec_result := C.KTAsendCommandreply(&c_request_data)
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

func terminateKTA() {
	teec_result := C.KTAterminate()
	if int(teec_result) != 0 {
		logger.L.Sugar().Errorf("terminate kta error, teec_result=%v", int(teec_result))
	}
}
