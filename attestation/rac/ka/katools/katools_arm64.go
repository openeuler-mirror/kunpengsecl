/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.
*/

package katools

/*
#cgo CFLAGS: -I../ktalib -I/opt/itrustee_sdk/include/CA
#cgo LDFLAGS: -L${SRCDIR}/../ktalib -lkta -ldl -lteec_adaptor
#include "ktalib.h"

*/
/*
//#cgo CFLAGS: -I../ktalib -I../teesimulator
//#cgo LDFLAGS: -L${SRCDIR}/../ktalib -lkta -Wl,-rpath=${SRCDIR}/../ktalib -lkta -ldl
//#include "ktalib.h"

*/
import "C"
import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"
	"unsafe"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
)

type hashValues struct {
	Uuid     string
	Mem_hash string
	Img_hash string
}

const (
	// CMD_DATA_SIZE means the size of cmd data
	CMD_DATA_SIZE = 2048
	tahashpath    = "./talist"
)

// KA主函数
// KaMain invokes KTA, establishes a connection to the clientapi,
// initializes ka, handles the polling key request process.
func KaMain(addr string, id int64, ktaShutdown bool) {
	logger.L.Debug("start ka...")
	loadConfigs()
	c_kta_path := C.CString(getKtaPath())
	defer C.free(unsafe.Pointer(c_kta_path))
	err := getContextSession(c_kta_path)
	if err != nil {
		logger.L.Sugar().Errorf("open session failed, %s", err)
		return
	}
	if ktaShutdown {
		terminateKTA()
		os.Exit(0)
	}
	defer C.KTAshutdown()
	ras, err := clientapi.CreateConn(addr)
	if err != nil {
		logger.L.Sugar().Errorf("connect ras server failed, %s", err)
		return
	}
	defer clientapi.ReleaseConn(ras)
	err1 := kaInitialize(ras, id)
	if err1 != nil {
		return
	}
	err2 := sendHashToKTA()
	if err2 != nil {
		logger.L.Sugar().Errorf("send ta hash values to kta failed, %s", err2)
		return
	}
	// 轮询密钥请求过程
	kaLoop(ras, id, getPollDuration(), addr)
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
	req := clientapi.VerifyKTAPubKeyCertRequest{
		ClientId:      id,
		KtaPubKeyCert: ktaCert,
	}
	// 向clientapi发送证书和设备id
	rpy, err := clientapi.DoVerifyKTAPubKeyCertWithConn(ras, &req)
	if err != nil || !rpy.Result {
		logger.L.Sugar().Errorf("kcm verify kta pubKeycert error, %s", err)
		terminateKTA()
		return err
	}
	logger.L.Debug("ka initialize done")
	return nil
}

// Read TA hash value from file named talist
func ReadHashValue() ([]byte, uint32, error) {
	var i uint32 = 0
	tahash, err := ioutil.ReadFile(tahashpath)
	if err != nil {
		logger.L.Sugar().Errorf("read ta hash failed, %s", err)
		terminateKTA()
		return nil, 0, err
	}
	lines := bytes.Split(tahash, typdefs.NewLine)
	map1 := make(map[string]hashValues)
	var subarray []byte
	for _, ln := range lines {
		if i >= 32 {
			break
		}
		// words[0]是uuid words[2]是mem_hash words[3]是img_hash
		words := bytes.Split(ln, typdefs.Space)
		if len(words) != 4 {
			continue
		}
		tahash := hashValues{
			Uuid:     string(words[0]),
			Mem_hash: string(words[2]),
			Img_hash: string(words[3]),
		}
		map1[fmt.Sprintf("%d", i)] = tahash
		i = i + 1
	}
	subarray, err1 := json.Marshal(map1)
	if err1 != nil {
		logger.L.Sugar().Errorf("marshal ta hash values to json format failed, %s", err1)
		terminateKTA()
		return nil, 0, err1
	}
	return subarray, i, nil
}
func getSendKtaData(kcm_cert *x509.Certificate) (*rsa.PublicKey, []byte, *rsa.PrivateKey, error) {
	kcmPubkey := kcm_cert.PublicKey.(*rsa.PublicKey)
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
	ktaPrivKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	return kcmPubkey, ktaPubCert, ktaPrivKey, nil
}
func removeKeyFile() {
	os.Remove(getKtaCertFile())
	os.Remove(getKtaKeyFile())
}

// 轮询函数
func kaLoop(ras *clientapi.RasConn, id int64, pollDuration time.Duration, addr string) {
	logger.L.Debug("start ka loop...")
	for {
		nextCmd, cmdnum, err := getKTACmd()
		if err != nil {
			logger.L.Sugar().Errorf("get kta command error, %s", err)
			break
		}
		if cmdnum == 0 {
			time.Sleep(1 * time.Second)
			continue
		}
		ras, err := clientapi.CreateConn(addr)
		if err != nil {
			logger.L.Sugar().Errorf("connect ras server fail, %s", err)
			return
		}
		defer clientapi.ReleaseConn(ras)
		req := clientapi.KeyOperationRequest{
			ClientId:   id,
			EncMessage: nextCmd,
		}

		logger.L.Sugar().Debugf("client id: %x, cmdlen: %d", id, len(nextCmd))
		// 向clientapi返回
		rpy, err := clientapi.DoKeyOperationWithConn(ras, &req)
		if err != nil {
			logger.L.Sugar().Errorf("do key operation withconn error, %s", err)
			break
		}
		err1 := sendRpyToKTA(rpy.EncRetMessage)
		if err1 != nil {
			logger.L.Sugar().Errorf("send rpy to kta error, %s", err1)
			break
		}
		logger.L.Debug("ka send reply to kta done")
		if cmdnum == 1 {
			time.Sleep(3 * time.Second)
			continue
		}
		clientapi.ReleaseConn(ras)
		time.Sleep(pollDuration)
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

// 初始化KTA
func initialKTA(kcmPubkey *rsa.PublicKey, ktaPubCert []byte, ktaPrivKey *rsa.PrivateKey) ([]byte, error) {
	// kcm pubkey: N
	c_kcmPubkey_N := C.CBytes(kcmPubkey.N.Bytes())
	defer C.free(c_kcmPubkey_N)
	c_request_data1 := C.struct_buffer_data{
		C.__uint32_t(len(kcmPubkey.N.Bytes())), (*C.uchar)(c_kcmPubkey_N)}
	// kcm pubkey certification
	c_ktaPubCert := C.CBytes(ktaPubCert)
	defer C.free(c_ktaPubCert)
	c_request_data2 := C.struct_buffer_data{
		C.__uint32_t(len(ktaPubCert)), (*C.uchar)(c_ktaPubCert)}
	// kta privkey: (N, D)
	c_ktaPrivKey_N := C.CBytes(ktaPrivKey.N.Bytes())
	defer C.free(c_ktaPrivKey_N)
	c_request_data3 := C.struct_buffer_data{
		C.__uint32_t(len(ktaPrivKey.N.Bytes())), (*C.uchar)(c_ktaPrivKey_N)}
	c_ktaPrivKey_D := C.CBytes(ktaPrivKey.D.Bytes())
	defer C.free(c_ktaPrivKey_D)
	c_request_data4 := C.struct_buffer_data{
		C.__uint32_t(len(ktaPrivKey.D.Bytes())), (*C.uchar)(c_ktaPrivKey_D)}
	// 返回值
	c_response_data := C.struct_buffer_data{}
	c_response_data.size = C.__uint32_t(len(ktaPubCert))
	c_response_data.buf = (*C.uint8_t)(C.malloc(C.ulong(c_response_data.size)))
	teec_result := C.KTAinitialize(
		&c_request_data1,
		&c_request_data2,
		&c_request_data3,
		&c_request_data4,
		&c_response_data)
	if int(teec_result) != 0 {
		return nil, errors.New("initial kta failed")
	}
	bk := C.GoBytes(unsafe.Pointer(c_response_data.buf), C.int(c_response_data.size))

	return bk, nil
}

// 向KTA发送TA哈希

func sendHashToKTA() error {
	hashvalue, hashnum, err := ReadHashValue()
	if err != nil {
		return err
	}
	c_cmd_data := C.struct_buffer_data{}
	c_cmd_num := C.uint(hashnum)
	c_cmd_data.size = C.__uint32_t(len(hashvalue))
	c_cmd_data.buf = (*C.uchar)(C.CBytes(hashvalue))
	defer C.free(unsafe.Pointer(c_cmd_data.buf))
	teec_result := C.KTAsendHash(&c_cmd_data, c_cmd_num)
	if int(teec_result) != 0 {
		return errors.New("invoke send hash command failed")
	}
	return nil
}

// 从KTA拿取密钥请求
func getKTACmd() ([]byte, uint32, error) {
	c_cmd_data := C.struct_buffer_data{}
	c_cmd_num := C.uint(0)
	c_cmd_data.size = C.__uint32_t(CMD_DATA_SIZE)
	c_cmd_data.buf = (*C.uint8_t)(C.malloc(C.ulong(c_cmd_data.size)))
	defer C.free(unsafe.Pointer(c_cmd_data.buf))
	teec_result := C.KTAgetCommand(&c_cmd_data, &c_cmd_num)
	if int(teec_result) != 0 {
		return nil, 0, errors.New("get kta commmand failed")
	}
	bk := C.GoBytes(unsafe.Pointer(c_cmd_data.buf), C.int(c_cmd_data.size))
	cmd_num := uint32(c_cmd_num)

	return bk, cmd_num, nil
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
	// check the period validate
	timeNow := time.Now()
	if !timeNow.Before(parent.NotAfter) {
		return errors.New("the certificate has expired")
	}
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
