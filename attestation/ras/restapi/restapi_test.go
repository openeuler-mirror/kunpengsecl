/*
Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: gwei3/zhuxiaolian
Create: 2023-02-07
Description: provide rest api to outside to control ras server.


The following comments are just for test and make the rest api understand easily.

curl -X POST -H "Accept: application/json" -H "Content-type: application/json" -d "{'name':'Joe', 'email':'joe@example.com'}" http://localhost:40002/
curl -X POST -H "Content-type: application/json" -d "{'name':'Joe', 'email':'joe@example.com'}" http://localhost:40002/
curl -X GET -H "Content-type: application/json" http://localhost:40002/
curl -X GET http://localhost:40002/

GET /version            显示当前rest api版本信息
POST /login             采用账号密码方式登录的入口
GET/POST /config        对RAS进行运行时配置的入口
GET /                   显示所有server的基本信息
GET /{from}/{to}        显示指定从from到to的server的基本信息

GET     /{id}                   显示指定server的基本信息
POST    /{id}                   修改指定server的基本信息
DELETE  /{id}                   删除指定server
GET     /{id}/reports           显示指定server的所有可信报告
GET     /{id}/reports/{rid}     显示指定server的指定可信报告
DELETE  /{id}/reports/{rid}     删除指定server的指定可信报告
GET     /{id}/basevalues        显示指定server的所有基准值
POST    /{id}/basevalues        新增指定server的基准值
GET     /{id}/basevalues/{bid}  显示指定server的指定基准值
POST    /{id}/basevalues/{bid}  修改指定server的指定基准值
DELETE  /{id}/basevalues/{bid}  删除指定server的指定基准值
*/

// restapi package provides the restful api interface based on openapi standard.
package restapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/internal"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

const (
	constinfo           = `{"ip": "8.8.8.%d", "name": "google DNS", "last": %d}`
	consttimeformat     = "06-01-02-15-04-05"
	constregisterfailed = "register fail %v"
	constPath           = "/reports"
	constDB             = "postgres"
	constDNS            = "user=postgres password=postgres dbname=kunpengsecl host=localhost port=5432 sslmode=disable"
	configFilePath      = "./config.yaml"
	rimcertFilePath     = "./rimcert.crt"
	ecdsakeyPath        = "./ecdsakey.pub"
	three               = 3
	ten                 = 10
	readwrite           = 0644
	serverConfig        = `
database:
  host: localhost
  dbname: kunpengsecl
  port: 5432
  user: "postgres"
  password: "postgres"
rasconfig:
  rootprivkeyfile: ""
  rootkeycertfile: ""
  pcaprivkeyfile: ""
  pcakeycertfile: ""
  port: "127.0.0.1:40001"
  rest: "127.0.0.1:40002"
  changetime: 0
  httpsSwitch: 0
  verboseFlag: true
  taVerifyType: true
  mgrstrategy: auto
  rimRootCertFile: ./rimcert.crt
  authkeyfile: ./ecdsakey.pub
  basevalue-extract-rules:
    pcrinfo:
      pcrselection: [1, 2, 3, 4]
    manifest:
      - type: bios
        name: ["name1", "name2"]
      - type: ima
        name: ["name1", "name2"]
  auto-update-config:
    isAllUpdate: false
    update-clients: [1, 2, 3]
racconfig:
  hbduration: 5s
  trustduration: 2m0s
  digestalgorithm: sha256
`
)
const (
	rim1 = `
<?xml version="1.0" encoding="ISO-8859-1"?>
<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:n8060="http://csrc.nist.gov/ns/swid/2015-extensions/1.0" xml:lang="en-US" supplemental="false" patch="false" corpus="false" tagVersion="0" tagId="94f6b457-9ac9-4d35-9b3f-78804173b651" version="01" versionScheme="alphanumeric" name="Example.com IOTCore">
  <Entity name="Example Inc." role="softwareCreator tagCreator" regid="http://Example.com"/>
  <Link href="https://Example.com/support/ProductA/firmware/installfiles" rel="installationmedia"/>
  <Meta xmlns:rim="https://trustedcomputinggroup.org/wp-content/uploads/TCG_RIM_Model" colloquialVersion="Firmware_2019" edition="IOT" product="ProductA" revision="r2" rim:pcURILocal="/boot/tcg/manifest/swidtag" rim:BindingSpec="IOT RIM" rim:BindingSpecVersion="1.2" rim:PlatformManufacturerId="00201234" rim:PlatformManufacturerStr="Example.com" rim:PlatformModel="ProductA" rim:FirmwareManufacturer="BIOSVendorA" rim:FirmwareManufacturerId="00213022" rim:RIMLinkHash="88f21d8e44d4271149297404df91caf207130bfa116582408abd04ede6db7f51"/>
  <Payload xmlns:SHA256="http://www.w3.org/2001/04/xmlenc#sha256" n8060:envVarPrefix="$" n8060:envVarSuffix="" n8060:pathSeparator="/">
    <Directory name="iotBase" location="/boot/iot/">
      <File name="Example.com.iotBase.bin" version="01.00" size="15400" SHA256:hash="a314fc2dc663ae7a6b6bc6787594057396e6b3f569cd50fd5ddb4d1bbafd2b6a"/>
      <File name="iotExec.bin" version="01.00" size="1024" SHA256:hash="532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"/>
    </Directory>
  </Payload>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>5qotN58t7O9rOaExWCQVZeQ1eB0zEZYffhPL/456A3k=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Rw94aph/jtIMLPqOK9p5JzNQqype3RF/whQC1BbeS1+RaSEgNkZUL79VWfxWUZzMb0BEbSDYsvkoj8dXJI/BHxgFWOTn7Dz3HKAlmFPHy9rQAb71gbZwEPRcfzG4O8FpTC3NY1PD/LnE64W3BgenELyExDku2kdYmUk0Rd3KV6c=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBlTCB/6ADAgECAgEAMA0GCSqGSIb3DQEBCwUAMAAwHhcNMjIwODI2MTA1MTQ2WhcNMjMwODI2MTA1NjQ2WjAAMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDarFEx7VQs58UPb7onvNBRIe2Ltwxjb9o3aR5dG5wN0ndXlPdjQm+hqMNlZ6nw7lfLeOn1m33VVxrUFbqNfR9skYMMocKwBqthIBQdhZyTb0GRzyiS3hLIHmSGyHEEquWfsEYHH7hZYcgFDDOviL2GUJnwsMXpcD7jy0FTCumcVwIDAQABoyAwHjAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOBgQC2rVIyMZLsO+LaNAri1Vz7wbfXVFthNXkRFovY2ycQax6zPDMJan8N2ERbeO9rFHz6bwQRej7y2Le50QYUQfxAIZT1Is9P8O73PGLPyZSM0hRqqSQmoSs75V36A3pfQhdPMPRBs8//PI4rw2MkMK04BCDlWcXWfIhBGHsfa+nVJQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></SoftwareIdentity>
`
	cert1 = `
-----BEGIN CERTIFICATE-----
MIIBlTCB/6ADAgECAgEAMA0GCSqGSIb3DQEBCwUAMAAwHhcNMjIwODI2MTA1MTQ2
WhcNMjMwODI2MTA1NjQ2WjAAMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDa
rFEx7VQs58UPb7onvNBRIe2Ltwxjb9o3aR5dG5wN0ndXlPdjQm+hqMNlZ6nw7lfL
eOn1m33VVxrUFbqNfR9skYMMocKwBqthIBQdhZyTb0GRzyiS3hLIHmSGyHEEquWf
sEYHH7hZYcgFDDOviL2GUJnwsMXpcD7jy0FTCumcVwIDAQABoyAwHjAOBgNVHQ8B
Af8EBAMCB4AwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOBgQC2rVIyMZLs
O+LaNAri1Vz7wbfXVFthNXkRFovY2ycQax6zPDMJan8N2ERbeO9rFHz6bwQRej7y
2Le50QYUQfxAIZT1Is9P8O73PGLPyZSM0hRqqSQmoSs75V36A3pfQhdPMPRBs8//
PI4rw2MkMK04BCDlWcXWfIhBGHsfa+nVJQ==
-----END CERTIFICATE-----
`
	result1 = `ima-ng sha256:a314fc2dc663ae7a6b6bc6787594057396e6b3f569cd50fd5ddb4d1bbafd2b6a /
	boot/iot/iotBase/Example.com.iotBase.bin\nima-ng sha256:532eaabd9574880dbf76b9b8cc00832c20
	a6ec113d682299550d7a6e0f345e25 /boot/iot/iotBase/iotExec.bin\n`
)

const ecdsakey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnEwqCEpLwzEVvjIDTaZNSKjUprQI
6K2x5pynyMeKSePduw9DPiZNx+Mh+06XcDPotf/dW8Sgust0CwKIvQ9iaQ==
-----END PUBLIC KEY-----
`

var (
	duration  = []time.Duration{time.Second, time.Second * three, time.Millisecond * ten}
	ik        = "IK" + time.Now().Format(consttimeformat) + "KA"
	info      = fmt.Sprintf(constinfo, time.Now().Second(), time.Now().Second())
	validated = true
	tauuid    = "ta1"
	uuid      = "uuid"
)

func CreateServerConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(serverConfig), readwrite)
}

func RemoveConfigFile() {
	os.Remove(configFilePath)
}

func RemoveFiles() {
	os.Remove("./pca-root.crt")
	os.Remove("./pca-root.key")
	os.Remove("./pca-ek.crt")
	os.Remove("./pca-ek.key")
	os.Remove("./https.crt")
	os.Remove("./https.key")
}

func prepare() bool {
	CreateServerConfigFile()
	savefile(rimcertFilePath, []byte(cert1))
	config.LoadConfigs()
	config.HandleFlags()
	trustmgr.CreateTrustManager(constDB, constDNS)
	savefile(ecdsakeyPath, []byte(ecdsakey))
	https := config.GetHttpsSwitch()
	return https
}

func release() {
	RemoveConfigFile()
	removefile(rimcertFilePath)
	RemoveFiles()
	removefile(ecdsakeyPath)
	trustmgr.ReleaseTrustManager()
	StopServer()
}

func TestCreateTestAuthToken(t *testing.T) {
	_, err := CreateTestAuthToken()
	if err != nil {
		fmt.Printf("CreateTestAuthToken failed: %v\n", err)
	}
	// fmt.Printf("please pass below line as a whole in http Authorization header:\nBearer %s\n", string(token))
}

func TestGet(t *testing.T) {
	config.InitFlags()
	https := prepare()
	defer release()
	go StartServer(https)

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err := s.Get(ctx)
	if err != nil {
		t.Errorf("test Get failed %v", err)
	}
}

func TestGetConfig(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)

	e1 := echo.New()
	req1 := httptest.NewRequest(echo.GET, "/", nil)
	req1.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec1 := httptest.NewRecorder()
	ctx1 := e1.NewContext(req1, rec1)

	s := &MyRestAPIServer{}
	err := s.GetConfig(ctx1)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec1.Code)
		t.Log(rec1.Body)
	}

	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	err = s.GetConfig(ctx2)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec2.Code)
		t.Log(rec2.Body)
	}
}

func TestPostconfig(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)

	var duration time.Duration = time.Second
	isautoUpdate := true
	loggermode := true
	vtype := 1
	manual := "manual"
	algorithm256 := "sha256"
	extractrule := "PcrRule"
	tavaluetype := 1
	config.SetIsAllUpdate(isautoUpdate)
	config.SetLoggerMode(!loggermode)
	config.SetTaVerifyType(vtype)
	cfginfo := cfgRecord{
		HBDuration:      duration.String(),
		TrustDuration:   duration.String(),
		IsAllupdate:     &isautoUpdate,
		LogTestMode:     &loggermode,
		DigestAlgorithm: algorithm256,
		MgrStrategy:     manual,
		ExtractRules:    extractrule,
		TaVerifyType:    tavaluetype,
	}
	cfgjson, err := json.Marshal(cfginfo)
	assert.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(string(cfgjson)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err = s.PostConfig(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}

	e2 := echo.New()
	req2 := httptest.NewRequest(echo.POST, "/", nil)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	err = s.PostConfig(ctx2)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec2.Code)
	}
}

func TestGetLogin(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err := s.GetLogin(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}

	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	err = s.GetLogin(ctx2)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec2.Code)
	}
}

func TestGetVersion(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)

	e1 := echo.New()
	req1 := httptest.NewRequest(echo.GET, "/", nil)
	rec1 := httptest.NewRecorder()
	ctx1 := e1.NewContext(req1, rec1)

	s := &MyRestAPIServer{}
	err := s.GetVersion(ctx1)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec1.Code)
		t.Log(rec1.Body)
	}

	e2 := echo.New()
	// versionjson := `[{"version": "2.16"}]`
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	err = s.GetVersion(ctx2)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec2.Code)
		t.Log(rec2.Body)
	}
}

func TestGetFromTo(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	clients := []struct {
		IK   string
		Info string
	}{
		{"1", `{"ip": "10.0.0.1", "name": "wucaijun1", "num": 123}`},
		{"2", `{"ip": "10.0.0.2", "name": "wucaijun2", "num": 123}`},
		{"3", `{"ip": "10.0.0.3", "name": "wucaijun3", "num": 123}`},
		{"4", `{"ip": "10.0.0.4", "name": "wucaijun4", "num": 123}`},
		{"5", `{"ip": "10.0.0.5", "name": "wucaijun5", "num": 123}`},
		{"6", `{"ip": "10.0.0.6", "name": "wucaijun6", "num": 123}`},
		{"7", `{"ip": "10.0.0.7", "name": "wucaijun7", "num": 123}`},
	}
	tt := time.Now().Format("06-01-02-15-04-05.999")
	for _, c := range clients {
		trustmgr.RegisterClientByIK(c.IK+tt, c.Info, true)
		c1, err := trustmgr.FindClientByIK(c.IK + tt)
		if err != nil {
			t.Errorf("FindClientByIK failed, err: %s", err)
		}
		defer trustmgr.DeleteClientByID(c1.ID)
	}
	length := len(clients)
	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err := s.GetFromTo(ctx, 1, int64(length))
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}
	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	err = s.GetFromTo(ctx2, 1, int64(length))
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec2.Code)
	}
}

func TestDeleteId(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c1, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c1.ID)
	e1 := echo.New()
	req1 := httptest.NewRequest(echo.GET, "/", nil)
	rec1 := httptest.NewRecorder()
	ctx1 := e1.NewContext(req1, rec1)

	s := &MyRestAPIServer{}
	err = s.DeleteId(ctx1, c1.ID)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec1.Code)
		t.Log(rec1.Body)
	}

	c2, err := trustmgr.RegisterClientByIK(ik+"KA2", info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c2.ID)
	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	err = s.DeleteId(ctx2, c2.ID)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec2.Code)
		t.Log(rec2.Body)
	}
}

func TestGetId(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err = s.GetId(ctx, c.ID)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body)
	}

	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	err = s.GetId(ctx2, c.ID)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec2.Code)
		t.Log(rec2.Body)
	}
}

func TestIdBasevalues(t *testing.T) {
	t.Log("Get id base values as follows:")
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)
	baseRow1 := &typdefs.BaseRow{
		ClientID:   c.ID,
		CreateTime: time.Now(),
		Uuid:       "abc",
		Enabled:    true,
	}
	baseRow2 := &typdefs.BaseRow{
		ClientID:   c.ID,
		CreateTime: time.Now(),
		Uuid:       "def",
	}
	trustmgr.InsertBaseValue(baseRow1)
	trustmgr.InsertBaseValue(baseRow2)

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err = s.GetIdBasevalues(ctx, c.ID)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}
	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	err = s.GetIdBasevalues(ctx2, c.ID)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec2.Code)
		t.Log(rec2.Body)
	}
	c1row, err := trustmgr.FindBaseValuesByClientID(c.ID)
	if err != nil {
		t.Errorf("FindBaseValuesByClientID failed, err: %s", err)
	}
	for _, c1 := range c1row {
		defer trustmgr.DeleteBaseValueByID(c1.ID)
	}
}

func TestGetIdBasevaluesBasevalueid(t *testing.T) {
	t.Log("Get id base values as follows:")
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)
	baseRow1 := &typdefs.BaseRow{
		ClientID:   c.ID,
		CreateTime: time.Now(),
		Uuid:       "abc",
		Enabled:    true,
	}
	baseRow2 := &typdefs.BaseRow{
		ClientID:   c.ID,
		CreateTime: time.Now(),
		Uuid:       "def",
	}
	trustmgr.InsertBaseValue(baseRow1)
	trustmgr.InsertBaseValue(baseRow2)

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	c1row, err := trustmgr.FindBaseValuesByClientID(c.ID)
	if err != nil {
		t.Errorf("FindBaseValuesByClientID failed, err: %s", err)
	}
	for _, c1 := range c1row {
		err = s.GetIdBasevaluesBasevalueid(ctx, c.ID, c1.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec.Code)
		}
		err = s.GetIdBasevaluesBasevalueid(ctx2, c.ID, c1.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec2.Code)
			t.Log(rec2.Body)
		}
		defer trustmgr.DeleteBaseValueByID(c1.ID)
	}
}

func TestDeleteIdBasevaluesBasevalueid(t *testing.T) {
	t.Log("Get id base values as follows:")
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)
	baseRow1 := &typdefs.BaseRow{
		ClientID:   c.ID,
		CreateTime: time.Now(),
		Uuid:       "abc",
		Enabled:    true,
	}
	baseRow2 := &typdefs.BaseRow{
		ClientID:   c.ID,
		CreateTime: time.Now(),
		Uuid:       "def",
	}
	trustmgr.InsertBaseValue(baseRow1)
	trustmgr.InsertBaseValue(baseRow2)

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	c1row, err := trustmgr.FindBaseValuesByClientID(c.ID)
	if err != nil {
		t.Errorf("FindBaseValuesByClientID failed, err: %s", err)
	}
	for _, c1 := range c1row {
		err = s.DeleteIdBasevaluesBasevalueid(ctx, c.ID, c1.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec.Code)
		}
		err = s.DeleteIdBasevaluesBasevalueid(ctx2, c.ID, c1.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec2.Code)
		}
	}
}

func TestPostId(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)

	cache1, err := trustmgr.GetCache(c.ID)
	if err != nil {
		t.Errorf("GetCache failed, error: %v", err)
	}
	cache1.SetIsAutoUpdate(true)
	registered := true
	isautoUpdate := false
	cinfo := clientInfo{
		Registered:   &registered,
		IsAutoUpdate: &isautoUpdate,
	}
	infojson, err := json.Marshal(cinfo)
	assert.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(string(infojson)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	s := &MyRestAPIServer{}
	err = s.PostId(ctx, c.ID)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func Unmarshalbasevalue(basetype string) ([]byte, error) {
	basevalue := baseValueJson{
		BaseType: basetype,
		Enabled:  true,
	}
	basevaluejson, err := json.Marshal(basevalue)
	if err != nil {
		return nil, err
	}
	return basevaluejson, nil
}

func postidbasevalue(t *testing.T, clientid int64, json bool) {
	baseRow := &typdefs.BaseRow{
		ClientID:   clientid,
		CreateTime: time.Now(),
		Uuid:       "abc",
	}
	trustmgr.InsertBaseValue(baseRow)
	b, err := trustmgr.FindBaseValueByUuid(baseRow.Uuid)
	assert.NoError(t, err)
	defer trustmgr.DeleteBaseValueByID(b.ID)
	cache1, err := trustmgr.GetCache(clientid)
	assert.NoError(t, err)
	cache1.SetBases(baseRow)
	defer cache1.ClearBases()
	basevaluejson, err := Unmarshalbasevalue(typdefs.StrHost)
	assert.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(string(basevaluejson)))
	if json {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err = s.PostIdBasevaluesBasevalueid(ctx, clientid, b.ID)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusFound, rec.Code)
		t.Log(rec.Body)
	}
	for _, base := range cache1.Bases {
		e1 := echo.New()
		req1 := httptest.NewRequest(echo.POST, "/", strings.NewReader(string(basevaluejson)))
		if json {
			req1.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		}
		rec1 := httptest.NewRecorder()
		ctx1 := e1.NewContext(req1, rec1)
		err = s.PostIdBasevaluesBasevalueid(ctx1, clientid, base.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusFound, rec1.Code)
			t.Log(rec1.Body)
		}
	}
}

func TestPostIdBasevaluesBasevalueid(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)

	postidbasevalue(t, c.ID, true)
	postidbasevalue(t, c.ID, false)
}

func TestGetIdNewbasevalue(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)

	baseRow := &typdefs.BaseRow{
		ClientID:   c.ID,
		CreateTime: time.Now(),
		Uuid:       "abc",
	}
	trustmgr.InsertBaseValue(baseRow)
	b, err := trustmgr.FindBaseValueByUuid(baseRow.Uuid)
	if err != nil {
		t.Errorf("FindBaseValueByUuid failed, err: %s", err)
	}
	defer trustmgr.DeleteBaseValueByID(b.ID)

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err = s.GetIdNewbasevalue(ctx, c.ID)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func savefile(path string, data []byte) {
	ioutil.WriteFile(path, []byte(data), readwrite)
}

func removefile(path string) {
	os.Remove(path)
}

func testPostNBValueByJson(t *testing.T, clientid int64) {
	basevalue := baseValueJson{
		BaseType:   typdefs.StrHost,
		Enabled:    true,
		IsNewGroup: true,
	}
	basevaluejson1, err := json.Marshal(basevalue)
	assert.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(string(basevaluejson1)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err = s.PostIdNewbasevalue(ctx, clientid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body)
	}
}

func testPostNBValueByXml(t *testing.T, clientid int64) {
	rootcert := config.GetRimRootCert()
	if rootcert != nil {
		t.Log("=====")
	} else {
		t.Log("-----")
	}
	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(string(rim1)))
	req.Header.Set(echo.HeaderContentType, echo.MIMETextXML)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err := s.PostIdNewbasevalue(ctx, clientid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body)
	}
}

func testPostNBValueByMultiForm(t *testing.T, clientid int64) {
	postData := make(map[string]string)
	postData[strName] = "name1"
	postData[strBaseType] = typdefs.StrHost
	postData[strEnabled] = "true"
	postData[strIsNewGroup] = "true"
	body := new(bytes.Buffer)
	w := multipart.NewWriter(body)
	for k, v := range postData {
		err := w.WriteField(k, v)
		assert.NoError(t, err)
	}
	err := w.Close()
	assert.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", body)
	// req3.Header.Set(echo.HeaderContentType, echo.MIMEMultipartForm)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err = s.PostIdNewbasevalue(ctx, clientid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusFound, rec.Code)
	}
}

func testPostIdNewBaseValue(t *testing.T, clientid int64, contentType string) {
	switch contentType {
	case echo.MIMEApplicationJSON:
		testPostNBValueByJson(t, clientid)
	case echo.MIMETextXML:
		testPostNBValueByXml(t, clientid)
	case echo.MIMEMultipartForm:
		testPostNBValueByMultiForm(t, clientid)
	default:
		t.Error("please input correct contentType")
	}

	rows, err := trustmgr.FindBaseValuesByClientID(clientid)
	if err != nil {
		t.Errorf("FindBaseValuesByClientID failed, error: %v", err)
	}
	for _, row := range rows {
		defer trustmgr.DeleteBaseValueByID(row.ID)
	}
}
func TestPostIdNewbasevalue(t *testing.T) {
	savefile(rimcertFilePath, []byte(cert1))
	defer removefile(rimcertFilePath)
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)

	testPostIdNewBaseValue(t, c.ID, echo.MIMEApplicationJSON)
	testPostIdNewBaseValue(t, c.ID, echo.MIMETextXML)
	testPostIdNewBaseValue(t, c.ID, echo.MIMEMultipartForm)
}

func insertreport(clientid int64, createtime time.Time, validated bool) {
	row := &typdefs.ReportRow{
		ClientID:   clientid,
		CreateTime: createtime,
		Validated:  validated,
	}
	trustmgr.InsertReport(row)
}

func TestGetIdReportsReportid(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	assert.NoError(t, err)
	defer trustmgr.DeleteClientByID(c.ID)
	insertreport(c.ID, time.Now(), validated)
	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err = s.GetIdReports(ctx, c.ID)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}
	c1, err := trustmgr.FindReportsByClientID(c.ID)
	assert.NoError(t, err)
	if len(c1) != 0 {
		err = s.GetIdReportsReportid(ctx, c.ID, c1[0].ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec.Code)
		}
		defer trustmgr.DeleteReportByID(c1[0].ID)
	}
	createtime, err := time.Parse("01-02-2006", "06-17-2013")
	assert.NoError(t, err)
	insertreport(c.ID, createtime, validated)
	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	err = s.GetIdReports(ctx2, c.ID)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec2.Code)
		t.Log(rec2.Body)
	}
	c2, err := trustmgr.FindReportsByClientID(c.ID)
	assert.NoError(t, err)
	if len(c2) != 0 {
		err = s.GetIdReportsReportid(ctx2, c.ID, c2[0].ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec2.Code)
			t.Log(rec2.Body)
		}
		defer trustmgr.DeleteReportByID(c2[0].ID)
	}
}

func TestDeleteIdReportsReportid(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	assert.NoError(t, err)
	defer trustmgr.DeleteClientByID(c.ID)
	insertreport(c.ID, time.Now(), validated)
	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err = s.GetIdReports(ctx, c.ID)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}
	c1, err := trustmgr.FindReportsByClientID(c.ID)
	assert.NoError(t, err)
	if len(c1) != 0 {
		err = s.DeleteIdReportsReportid(ctx, c.ID, c1[0].ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec.Code)
		}
		defer trustmgr.DeleteReportByID(c1[0].ID)
	}
	createtime, err := time.Parse("01-02-2006", "06-17-2013")
	assert.NoError(t, err)
	insertreport(c.ID, createtime, validated)
	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	err = s.GetIdReports(ctx2, c.ID)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec2.Code)
		t.Log(rec2.Body)
	}
	c2, err := trustmgr.FindReportsByClientID(c.ID)
	assert.NoError(t, err)
	if len(c2) != 0 {
		err = s.DeleteIdReportsReportid(ctx2, c.ID, c2[0].ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec2.Code)
			t.Log(rec2.Body)
		}
		defer trustmgr.DeleteReportByID(c2[0].ID)
	}
}

func TestGetIdContainerStatus(t *testing.T) {
	GetIdStatus(t, strContainer)
	GetIdStatus(t, strDevice)
}

func cacheSetBases(cache *cache.Cache, clientid int64, basetype string, verified bool, trusted bool) {
	baserow := &typdefs.BaseRow{
		ClientID:   clientid,
		BaseType:   basetype,
		Uuid:       uuid,
		CreateTime: time.Now(),
		Verified:   verified,
		Trusted:    trusted,
	}
	cache.SetBases(baserow)
}

func GetIdStatus(t *testing.T, basetype string) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Errorf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)

	cache1, err := trustmgr.GetCache(c.ID)
	if err != nil {
		t.Errorf("GetCache failed, error: %v", err)
	}
	cacheSetBases(cache1, c.ID, typdefs.StrHost, true, false)
	cacheSetBases(cache1, c.ID, basetype, false, true)
	cacheSetBases(cache1, c.ID, basetype, true, true)
	cacheSetBases(cache1, c.ID, basetype, true, false)
	cache1.UpdateTrustReport(duration[0])
	defer cache1.ClearBases()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	if basetype == strContainer {
		err = s.GetIdContainerStatus(ctx, c.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec.Code)
			t.Log(rec.Body)
		}
	} else {
		err = s.GetIdDeviceStatus(ctx, c.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec.Code)
			t.Log(rec.Body)
		}
	}
}

func TestGetIdTaTauuidNewtabasevalue(t *testing.T) {
	config.SetHttpsSwitch("1")
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Errorf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err = s.GetIdTaTauuidNewtabasevalue(ctx, c.ID, tauuid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body)
	}
}

func testPostIdTaNewBaseValue(t *testing.T, clientid int64, contentType string) {
	switch contentType {
	case echo.MIMEApplicationJSON:
		testPostTaNBValueByJson(t, clientid)
	case echo.MIMETextXML:
		testPostTaNBValueByXml(t, clientid)
	case echo.MIMEMultipartForm:
		testPostTaNBValueByMultiForm(t, clientid)
	default:
		t.Error("please input correct contentType")
	}

	tarows, err := trustmgr.FindTaBaseValuesByCid(clientid)
	if err != nil {
		t.Errorf("FindTaBaseValuesByCid failed error: %v", err)
	}
	for _, tarow := range tarows {
		defer trustmgr.DeleteTaBaseValueByID(tarow.ID)
	}
}

func testPostTaNBValueByJson(t *testing.T, clientid int64) {
	tabasevalue := tabaseValueJson{
		Uuid:      tauuid,
		Name:      "wucaijun",
		Enabled:   true,
		Valueinfo: "value",
	}
	tabasevaluejson1, err := json.Marshal(tabasevalue)
	assert.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(string(tabasevaluejson1)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err = s.PostIdTaTauuidNewtabasevalue(ctx, clientid, tauuid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body)
	}
}

func testPostTaNBValueByXml(t *testing.T, clientid int64) {
	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(string(rim1)))
	req.Header.Set(echo.HeaderContentType, echo.MIMETextXML)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err := s.PostIdTaTauuidNewtabasevalue(ctx, clientid, tauuid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body)
	}
}

func testPostTaNBValueByMultiForm(t *testing.T, clientid int64) {
	postData := make(map[string]string)
	postData[strName] = "wucaijun2"
	body := new(bytes.Buffer)
	w := multipart.NewWriter(body)
	for k, v := range postData {
		err := w.WriteField(k, v)
		assert.NoError(t, err)
	}
	err := w.Close()
	assert.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", body)
	// req3.Header.Set(echo.HeaderContentType, echo.MIMEMultipartForm)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err = s.PostIdTaTauuidNewtabasevalue(ctx, clientid, tauuid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusFound, rec.Code)
		t.Log(rec.Body)
	}

}
func TestPostIdTaTauuidNewtabasevalue(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)

	testPostIdTaNewBaseValue(t, c.ID, echo.MIMEApplicationJSON)
	testPostIdTaNewBaseValue(t, c.ID, echo.MIMETextXML)
	testPostIdTaNewBaseValue(t, c.ID, echo.MIMEMultipartForm)
}

func TestGetIdTaTauuidStatus(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Errorf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)

	cache1, err := trustmgr.GetCache(c.ID)
	if err != nil {
		t.Errorf("GetCache failed, error: %v", err)
	}
	cache1.UpdateHeartBeat(duration[0])
	cache1.UpdateTrustReport(duration[0])
	cache1.SetTaTrusted(tauuid, cache.StrTrusted)

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}

	err = s.GetIdTaTauuidStatus(ctx, c.ID, tauuid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body)
	}
}

func insertTaBase(clientid int64, tauuid string) {
	tabaseRow := &typdefs.TaBaseRow{
		ClientID:   clientid,
		CreateTime: time.Now(),
		Uuid:       tauuid,
	}
	trustmgr.InsertTaBase(tabaseRow)
}

func TestGetIdTaTauuidTabasevalues(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)
	insertTaBase(c.ID, tauuid)

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	err = s.GetIdTaTauuidTabasevalues(ctx, c.ID, tauuid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}
	c1rows, err := trustmgr.FindTaBaseValuesByUuid(c.ID, tauuid)
	assert.NoError(t, err)
	for _, c1row := range c1rows {
		trustmgr.DeleteTaBaseValueByID(c1row.ID)
	}

	insertTaBase(c.ID, tauuid)
	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	err = s.GetIdTaTauuidTabasevalues(ctx2, c.ID, tauuid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}
	c2rows, err := trustmgr.FindTaBaseValuesByUuid(c.ID, tauuid)
	assert.NoError(t, err)
	for _, c2row := range c2rows {
		trustmgr.DeleteTaBaseValueByID(c2row.ID)
	}
}

func TestGetIdTaTauuidTabasevaluesTabasevalueid(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)
	insertTaBase(c.ID, tauuid)

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	c1rows, err := trustmgr.FindTaBaseValuesByUuid(c.ID, tauuid)
	assert.NoError(t, err)
	for _, c1row := range c1rows {
		err = s.GetIdTaTauuidTabasevaluesTabasevalueid(ctx, c.ID, tauuid, c1row.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec.Code)
			t.Log(rec.Body)
		}
		defer trustmgr.DeleteTaBaseValueByID(c1row.ID)
	}

	insertTaBase(c.ID, tauuid)
	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	c2rows, err := trustmgr.FindTaBaseValuesByUuid(c.ID, tauuid)
	assert.NoError(t, err)
	for _, c2row := range c2rows {
		err = s.GetIdTaTauuidTabasevaluesTabasevalueid(ctx2, c.ID, tauuid, c2row.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec2.Code)
			t.Log(rec2.Body)
		}
		defer trustmgr.DeleteTaBaseValueByID(c2row.ID)
	}
}

func TestDeleteIdTaTauuidTabasevaluesTabasevalueid(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)
	insertTaBase(c.ID, tauuid)

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	c1rows, err := trustmgr.FindTaBaseValuesByUuid(c.ID, tauuid)
	assert.NoError(t, err)
	for _, c1row := range c1rows {
		err = s.DeleteIdTaTauuidTabasevaluesTabasevalueid(ctx, c.ID, tauuid, c1row.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec.Code)
			t.Log(rec.Body)
		}
		defer trustmgr.DeleteTaBaseValueByID(c1row.ID)
	}

	insertTaBase(c.ID, tauuid)
	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	c2rows, err := trustmgr.FindTaBaseValuesByUuid(c.ID, tauuid)
	assert.NoError(t, err)
	for _, c2row := range c2rows {
		err = s.DeleteIdTaTauuidTabasevaluesTabasevalueid(ctx2, c.ID, tauuid, c2row.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec2.Code)
			t.Log(rec2.Body)
		}
		defer trustmgr.DeleteTaBaseValueByID(c2row.ID)
	}
}

func testPostTaBasealueid(t *testing.T, clientid int64, contentType string) {
	switch contentType {
	case echo.MIMEApplicationJSON:
		testPostTaBasealueidByJson(t, clientid)
	case echo.MIMEMultipartForm:
		testPostTaBasevalueidByMultiForm(t, clientid)
	default:
		t.Error("please input correct contentType")
	}
}
func testPostTaBasealueidByJson(t *testing.T, clientid int64) {
	insertTaBase(clientid, tauuid)
	tabasevalue := tabaseValueJson{
		Uuid:      tauuid,
		Name:      "wucaijun",
		Enabled:   true,
		Valueinfo: "value",
	}
	tabasevaluejson1, err := json.Marshal(tabasevalue)
	assert.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(string(tabasevaluejson1)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	c1rows, err := trustmgr.FindTaBaseValuesByUuid(clientid, tauuid)
	assert.NoError(t, err)
	for _, c1row := range c1rows {
		err = s.PostIdTaTauuidTabasevaluesTabasevalueid(ctx, clientid, tauuid, c1row.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusFound, rec.Code)
			t.Log(rec.Body)
		}
		defer trustmgr.DeleteTaBaseValueByID(c1row.ID)
	}
}

func testPostTaBasevalueidByMultiForm(t *testing.T, clientid int64) {
	postData := make(map[string]string)
	postData[strName] = "wucaijun2"
	postData[strEnabled] = "true"
	body := new(bytes.Buffer)
	w := multipart.NewWriter(body)
	for k, v := range postData {
		err := w.WriteField(k, v)
		assert.NoError(t, err)
	}
	err := w.Close()
	assert.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", body)
	// req3.Header.Set(echo.HeaderContentType, echo.MIMEMultipartForm)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := &MyRestAPIServer{}
	c1rows, err := trustmgr.FindTaBaseValuesByUuid(clientid, tauuid)
	assert.NoError(t, err)
	for _, c1row := range c1rows {
		err := s.PostIdTaTauuidTabasevaluesTabasevalueid(ctx, clientid, tauuid, c1row.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusFound, rec.Code)
			t.Log(rec.Body)
		}
		defer trustmgr.DeleteTaBaseValueByID(c1row.ID)
	}
}

func TestPostIdTaTauuidTabasevaluesTabasevalueid(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)

	testPostTaBasealueid(t, c.ID, echo.MIMEApplicationJSON)
	testPostTaBasealueid(t, c.ID, echo.MIMEMultipartForm)
}

func insertTareport(clientid int64) {
	tareport := &typdefs.TaReportRow{
		ClientID:   clientid,
		CreateTime: time.Now(),
		Uuid:       tauuid,
	}
	trustmgr.InsertTaReport(tareport)
}
func TestGetIdTaTauuidTareports(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)
	insertTareport(c.ID)

	e1 := echo.New()
	req1 := httptest.NewRequest(echo.GET, "/", nil)
	req1.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec1 := httptest.NewRecorder()
	ctx1 := e1.NewContext(req1, rec1)
	s := &MyRestAPIServer{}
	err = s.GetIdTaTauuidTareports(ctx1, c.ID, tauuid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec1.Code)
		t.Log(rec1.Body)
	}

	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	err = s.GetIdTaTauuidTareports(ctx2, c.ID, tauuid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec2.Code)
		t.Log(rec2.Body)
	}

	c1rows, err := trustmgr.FindTaReportsByUuid(c.ID, tauuid)
	assert.NoError(t, err)
	for _, c1row := range c1rows {
		defer trustmgr.DeleteTaReportByID(c1row.ID)
	}
}

func TestGetIdTaTauuidTareportsTareportid(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)
	insertTareport(c.ID)

	e1 := echo.New()
	req1 := httptest.NewRequest(echo.GET, "/", nil)
	req1.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec1 := httptest.NewRecorder()
	ctx1 := e1.NewContext(req1, rec1)
	s := &MyRestAPIServer{}

	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)

	c1rows, err := trustmgr.FindTaReportsByUuid(c.ID, tauuid)
	assert.NoError(t, err)
	for _, c1row := range c1rows {
		err = s.GetIdTaTauuidTareportsTareportid(ctx1, c.ID, tauuid, c1row.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec1.Code)
			t.Log(rec1.Body)
		}

		err = s.GetIdTaTauuidTareportsTareportid(ctx2, c.ID, tauuid, c1row.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec2.Code)
			t.Log(rec2.Body)
		}
		defer trustmgr.DeleteTaReportByID(c1row.ID)
	}
}

func TestDeleteIdTaTauuidTareportsTareportid(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)
	insertTareport(c.ID)

	e1 := echo.New()
	req1 := httptest.NewRequest(echo.GET, "/", nil)
	req1.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec1 := httptest.NewRecorder()
	ctx1 := e1.NewContext(req1, rec1)
	s := &MyRestAPIServer{}

	c1rows, err := trustmgr.FindTaReportsByUuid(c.ID, tauuid)
	assert.NoError(t, err)
	for _, c1row := range c1rows {
		err = s.DeleteIdTaTauuidTareportsTareportid(ctx1, c.ID, tauuid, c1row.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec1.Code)
			t.Log(rec1.Body)
		}
		defer trustmgr.DeleteTaReportByID(c1row.ID)
	}

	insertTareport(c.ID)
	e2 := echo.New()
	req2 := httptest.NewRequest(echo.GET, "/", nil)
	rec2 := httptest.NewRecorder()
	ctx2 := e2.NewContext(req2, rec2)
	c2rows, err := trustmgr.FindTaReportsByUuid(c.ID, tauuid)
	assert.NoError(t, err)
	for _, c2row := range c2rows {
		err = s.DeleteIdTaTauuidTareportsTareportid(ctx2, c.ID, tauuid, c2row.ID)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec2.Code)
			t.Log(rec2.Body)
		}
		defer trustmgr.DeleteTaReportByID(c2row.ID)
	}
}

func TestGetJWS(t *testing.T) {
	https := prepare()
	defer release()
	go StartServer(https)
	c, err := trustmgr.RegisterClientByIK(ik, info, true)
	if err != nil {
		t.Logf(constregisterfailed, err)
	}
	defer trustmgr.DeleteClientByID(c.ID)

	token, err := CreateTestAuthToken()
	if err != nil {
		fmt.Printf("CreateTestAuthToken failed: %v\n", err)
	}
	// fmt.Printf("please pass below line as a whole in http Authorization header:\nBearer %s\n", string(token))
	StringToken := "Bearer " + string(token)
	req1 := httptest.NewRequest(echo.GET, "/", nil)
	_, err = getJWS(req1)
	if err != nil {
		t.Logf("getJWS failed, error: %v", err)
	}
	req1.Header.Set(echo.HeaderAuthorization, string(token))
	_, err = getJWS(req1)
	if err != nil {
		t.Logf("getJWS failed, error: %v", err)
	}
	req1.Header.Set(echo.HeaderAuthorization, StringToken)
	jws, err := getJWS(req1)
	if err != nil {
		t.Errorf("getJWS failed, error: %v", err)
	}
	v, err := internal.NewFakeAuthenticator(config.GetAuthKeyFile())
	if err != nil {
		t.Errorf("NewFakeAuthenticator failed error: %v", err)
	}
	jwtToken, err := v.ValidateJWS(jws)
	if err != nil {
		t.Errorf("ValidateJWS failed error: %v", err)
	}

	_, err = getScopes(jwtToken)
	if err != nil {
		t.Errorf("getScopes failed error: %v", err)
	}
}
