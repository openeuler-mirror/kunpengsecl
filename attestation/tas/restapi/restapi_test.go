/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: zengshuai
Create: 2023-03-18
Description: provide rest api to outside to control tas server.

The following comments are just for test and make the rest api understand easily.

curl -X GET -H "Content-type: application/json" http://localhost:40009/config
curl -X POST -H "Content-type: application/json" -d "{'name':'Joe', 'email':'joe@example.com'}" http://localhost:40009/config

GET/POST /config        对TAS进行运行时配置的入口
*/

// restapi package provides the restful api interface based on openapi standard.
package restapi

import (
	"fmt"
	"io/ioutil"
	"strings"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
	"github.com/stretchr/testify/assert"
	"github.com/labstack/echo/v4"
	"gitee.com/openeuler/kunpengsecl/attestation/tas/config"
	"gitee.com/openeuler/kunpengsecl/attestation/tas/restapi/internal"
)
	


const serverConfig = `
tasconfig:
  port: 127.0.0.1:40008
  rest: 127.0.0.1:40009
  akskeycertfile: ./ascert.crt
  aksprivkeyfile: ./aspriv.key
  huaweiitcafile: ./Huawei IT Product CA.pem
  DAA_GRP_KEY_SK_X: 65A9BF91AC8832379FF04DD2C6DEF16D48A56BE244F6E19274E97881A776543C
  DAA_GRP_KEY_SK_Y: 126F74258BB0CECA2AE7522C51825F980549EC1EF24F81D189D17E38F1773B56
  basevalue: ""
  authkeyfile: ./ecdsakey.pub
`
const (
	serverport = "127.0.0.1:40008"
	restport   = "127.0.0.1:40009"
)

const configFilePath = "./config.yaml"

const (
	asCertPath   = "./ascert.crt"
	asprivPath   = "./aspriv.key"
	huaweiPath   = "./Huawei IT Product CA.pem"
	ecdsakeyPath = "./ecdsakey.pub"
	readwrite    = 0644
	timeout 	 = 60*time.Second
)

const ecdsakey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnEwqCEpLwzEVvjIDTaZNSKjUprQI
6K2x5pynyMeKSePduw9DPiZNx+Mh+06XcDPotf/dW8Sgust0CwKIvQ9iaQ==
-----END PUBLIC KEY-----
`

const cert = `
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIURBG3rzn2SH3wruHaPKctA2pEqS8wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjEyMTcxMzE3MTRaFw0yMzEy
MTcxMzE3MTRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQC3FM8ErX6+Vcy4sf4DQexeLDRFrqaKOWEEi90MTjE+
aAuIV0Vy8tFgnvaVoznLD6J7LUhaT1xvVNEhsQpSp+BEdZ8kUtxNm91j4FBDE+V6
RxWbGPXcZhfVSmoc+dlwt5aCrAH03GAJOp6NWLBGA6LBN1X5yaT6hJJTq3ioC+K3
h/08Ub801Glnai4BECygUHp1qn7bFl9p2o5yRfL80MJxQKsq1dKvUY/+Dsxzdwcr
GVT68nstBjXbnoTAjyhIZepJvZmGKvoiEG0sQwi3dInEK5Q9QLZBAHPNS+M/3v9g
dW/F1QPYeFEtz7+Np9gUYs9GOkB5L6Cr+gXeFRfRiO1/g9BMzrFhkKYTgnLHpdwu
oWpDmmfcr8TcRgSZCZ9oAC41wcn5b8nuGNUbI8fGRKaDzEsprEID5gOVofsC2KZv
sD+9ATI3MBD95OKXIbE0zMaAx21EIUxe7HVWUTcNnHf9kBpVR8x27xa/AV4Qc89d
1pCYg0cm/4SpkuhzfP1VGdL935QQcVumR85nBNyX4l8c8239zbnIepUn8GzkRqi5
5dwqLzxAY96y2VYNT3pbuRd3qK+psuPlviSZ/NtebFETjzVbl6LRCsKmY2DknfBo
LyIEO7M06H6B15lbZjPEd0vil4R9gROl/7h9k8wP8rj68/BiCE32xvsXRyy5oDt4
bwIDAQABo1MwUTAdBgNVHQ4EFgQUv+5bJBMwfJN9pB0XhB+niXZu6lowHwYDVR0j
BBgwFoAUv+5bJBMwfJN9pB0XhB+niXZu6lowDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAgEACAIBde61vKD3PBLiYmgFtXErnRIkGm9EY8q/T74xv9vX
b04mry+LUHAKDx/M2wpfcGW2rAGaNGvgGvfhK/vKv9P7gNmIjZOGgSJm+lsKCr39
2NlROMsi08GGWRBQhZNEt5feaH5bcCGWjDHnNTL1Nhe/OOf1i74X7gX3WS1mD0O+
I9/TUznmNg7bZhICRswFHEymSHMxyOsvzG+f1ENUr6XKgXTWD89PNOJ0IzQsXq7V
W96YSM7EvW87AXWyioFi7B9TRHtSxK+/ZJz5joZos8X4/Yamve7OpX3jQnrxxh0W
vkNdJ1fiiYzEciyTHAVUTA1q/ZqewEUgVZYhIAbTCEV1h1PLrL3VHbzCrarWZqX1
+vSDOJoYBtAMfugcsYqgnIdYOSwpQjdan8rXIqhgk2rwAgmIjEWvRAvFhoOxO7Os
PhLgoeJo+JahmUjAfE8L/wW3k/3OJQy2eD+cAtUFWpOdMrmE5FtepUv6voM6N6Fa
Q+d69RUiN0XvVYlG/ZXIeHtPYk6cXxof7J3Tn8ieEKbT7OwuG7vxRodCGSao6o3i
uOdEBUnNkMadj7i265D8de8sOuQ7+pPu4lNBZGmF5XeaBEEynF8ts1rWrwM+lUgK
/bK1vXGMemom0NEsj6zAOd2GUBuhFP9WLYXh4SRTY/5PKVhAdL9oenaIxji99lQ=
-----END CERTIFICATE-----
`

const aspriv = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`

const huaweica = `
-----BEGIN CERTIFICATE-----
MIIEsTCCApmgAwIBAgIRdjl5z9FobnagzdStBIQZVIcwDQYJKoZIhvcNAQELBQAw
PDELMAkGA1UEBhMCQ04xDzANBgNVBAoTBkh1YXdlaTEcMBoGA1UEAxMTSHVhd2Vp
IEVxdWlwbWVudCBDQTAeFw0xNjEwMTgwNjUwNTNaFw00MTEwMTIwNjUwNTNaMD0x
CzAJBgNVBAYTAkNOMQ8wDQYDVQQKEwZIdWF3ZWkxHTAbBgNVBAMTFEh1YXdlaSBJ
VCBQcm9kdWN0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtKE3
0649koONgSJqzwKXpSxTwiGTGorzcd3paBGH75Zgm5GFv2K2TG3cU6seS6dt7Ig+
/8ntrcieQUttcWxpm2a1IBeohU1OTGFpomQCRqesDnlXXUS4JgZiDvPBzoqGCZkX
YRw37J5KM5TSZzdLcWgxAPjXvKPdLXfxGzhqg8GV1tTboqXoNEqVqOeViBjsjN7i
xIuu1Stauy9E0E5ZnSrwUjHc5QrR9CmWIu9D0ZJJp1M9VgcXy9evPhiHoz9o+KBd
fNwt4e/NymTqaPa+ngS/qZwI7A4tR4RKCMKFHJcsjaXwUb0RuIeCiPO3wPHgXmGL
uiKfyPV8SMLpE/wYaQIDAQABo4GsMIGpMB8GA1UdIwQYMBaAFCr4EFkngDUfp3y6
O58q5Eqqm5LqMEYGA1UdIAQ/MD0wOwYEVR0gADAzMDEGCCsGAQUFBwIBFiVodHRw
Oi8vc3VwcG9ydC5odWF3ZWkuY29tL3N1cHBvcnQvcGtpMA8GA1UdEwQIMAYBAf8C
AQAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQSijfs+XNX1+SDurVvA+zdrhFO
zzANBgkqhkiG9w0BAQsFAAOCAgEAAg1oBG8YFvDEecVbhkxU95svvlTKlrb4l77u
cnCNhbnSlk8FVc5CpV0Q7SMeBNJhmUOA2xdFsfe0eHx9P3Bjy+difkpID/ow7oBH
q2TXePxydo+AxA0OgAvdgF1RBPTpqDOF1M87eUpJ/DyhiBEE5m+QZ6VqOi2WCEL7
qPGRbwjAFF1SFHTJMcxldwF6Q/QWUPMm8LUzod7gZrgP8FhwhDOtGHY5nEhWdADa
F9xKejqyDCLEyfzsBKT8V4MsdAo6cxyCEmwiQH8sMTLerwyXo2o9w9J7+vRAFr2i
tA7TwGF77Y1uV3aMj7n81UrXxqx0P8qwb467u+3Rj2Cs29PzhxYZxYsuov9YeTrv
GfG9voXz48q8ELf7UOGrhG9e0yfph5UjS0P6ksbYInPXuuvrbrDkQvLBYb9hY78a
pwHn89PhRWE9HQwNnflTZS1gWtn5dQ4uvWAfX19e87AcHzp3vL4J2bCxxPXEE081
3vhqtnU9Rlv/EJAMauZ3DKsMMsYX8i35ENhfto0ZLz1Aln0qtUOZ63h/VxQwGVC0
OCE1U776UUKZosfTmNLld4miJnwsk8AmLaMxWOyRsqzESHa2x1t2sXF8s0/LW5T7
d+j7JrLzey3bncx7wceASUUL3iAzICHYr728fNzXKV6OcZpjGdYdVREpM26sbxLo
77rH32o=
-----END CERTIFICATE-----
`

func createFiles() {
	err := ioutil.WriteFile(configFilePath, []byte(serverConfig),readwrite)
	if err != nil {
		return
	}
	err1 := ioutil.WriteFile(asCertPath, []byte(cert), readwrite)
	if err1 != nil {
		return
	}
	err2 := ioutil.WriteFile(asprivPath, []byte(aspriv), readwrite)
	if err2 != nil {
		return
	}
	err3 := ioutil.WriteFile(huaweiPath, []byte(huaweica), readwrite)
	if err3 != nil {
		return
	}
	err4 := ioutil.WriteFile(ecdsakeyPath, []byte(ecdsakey), readwrite)
	if err4 != nil {
		return
	}
}

func removeFiles() {
	err := os.Remove(configFilePath)
	if err != nil {
		return
	}
	err1 := os.Remove(asCertPath)
	if err1 != nil {
		return
	}
	err2 := os.Remove(asprivPath)
	if err2 != nil {
		return
	}
	err3 := os.Remove(huaweiPath)
	if err3 != nil {
		return
	}
	err4 := os.Remove(ecdsakeyPath)
	if err4 != nil {
		return
	}
}
func StopServer() {
	if srv == nil {
		return
	}
	srv.Close()
	srv = nil
}


func TestGetConfig(t *testing.T){
	createFiles()
	defer removeFiles()
	
	config.LoadConfigs()
	config.InitializeAS()
	
	addr := config.GetRestPort()
	go StartServer(addr)
	defer StopServer()
	

	e := echo.New()
	s := &MyRestAPIServer{}

	req := httptest.NewRequest(echo.GET, "/", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	
	err := s.GetConfig(ctx)

	if assert.NoError(t,err){
		assert.Equal(t,http.StatusOK,rec.Code)
		t.Log(rec.Body)
	}
}


func TestPostConfig(t *testing.T){

	createFiles()
	defer removeFiles()
	
	config.LoadConfigs()
	config.InitializeAS()
	addr := config.GetRestPort()
	go StartServer(addr)
	defer StopServer()

	var configJSON0 = `{"basevalue":"testvalue"}`

	e := echo.New()
	s := &MyRestAPIServer{}
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(configJSON0))
	
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	err := s.PostConfig(ctx)
	_=err
	assert.Equal(t, http.StatusOK, rec.Code)


	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	

	ctx = e.NewContext(req, rec)
	
	
	err = s.PostConfig(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}
func TestStartServer(t *testing.T){
	createFiles()
	defer removeFiles()
	
	config.LoadConfigs()
	config.InitializeAS()
	
	addr := config.GetRestPort()
	

	go StartServer(addr)
	tmp := srv
	go StartServer(addr)
	if tmp != srv{
		t.Errorf("startserver failed")
	}
	defer StopServer()
	
}
func TestCreateTestAuthToken(t *testing.T){
	token, err := CreateTestAuthToken()
		if err != nil {
			t.Errorf("create test auth token failed: %v\n", err)
			
		}
		fmt.Printf("please pass below line as a whole in http Authorization header:\nBearer %s\n", string(token))
}

func TestGetJWS(t *testing.T){
	var authorizationtest0 = "Bearer eyJh"

	var authorizationtest1 = "eyJh"

	req := httptest.NewRequest(echo.GET, "/", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	_, err := getJWS(req)
	if err == nil{
		t.Errorf("error")
	}

	req.Header.Set("Authorization", authorizationtest0)
	_, err = getJWS(req)
	if err!=nil{
		t.Errorf("error")
	}

	req.Header.Set("Authorization", authorizationtest1)
	_, err = getJWS(req)
	if err == nil{
		t.Errorf("error")
	}

}



func TestGetScopes(t *testing.T){
	createFiles()
	defer removeFiles()
	//config.InitFlags()
	config.LoadConfigs()
	config.InitializeAS()
	addr := config.GetRestPort()
	
	
	go StartServer(addr)
	defer StopServer()

	token, err := CreateTestAuthToken()
	if err != nil {
		fmt.Printf("CreateTestAuthToken failed: %v\n", err)
	}
	
	StringToken := "Bearer " + string(token)
	req1 := httptest.NewRequest(echo.GET, "/", nil)
	req1.Header.Set(echo.HeaderAuthorization, StringToken)
	jws, err := getJWS(req1)
	if err != nil {
		t.Errorf("getJWS failed, error: %v", err)
	}
	v, err := internal.NewFakeAuthenticator(config.GetAuthKeyFile())
	if err != nil {
		t.Errorf("NewFakeAuthenticator failed error: %v", err)
	}
	_, err = CreateAuthValidator(v)
	if err != nil {
		t.Error(err)
	}
	jwtToken, err := v.ValidateJWS(jws)
	if err != nil {
		t.Errorf("ValidateJWS failed error: %v", err)
	}

	cls, err := getScopes(jwtToken)
	if err != nil {
		t.Errorf("getScopes failed error: %v", err)
	}
	
	err = checkScopes(cls,jwtToken)
	if err != nil{
		t.Errorf("checkScopes failed error: %v", err)
	}
	
}

func TestCheckJSON(t *testing.T){
	e := echo.New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(echo.GET, "/", nil)
	ctx := e.NewContext(req, rec)
	if(checkJSON(ctx)){
		t.Errorf("checkJSON failed")
	}
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	ctx = e.NewContext(req, rec)
	if(!checkJSON(ctx)){
		t.Errorf("checkJSON failed")
	}
}


func TestCreateAuthValidator(t *testing.T){
	createFiles()
	defer removeFiles()
	//config.InitFlags()
	config.LoadConfigs()
	config.InitializeAS()
	addr := config.GetRestPort()
	
	
	go StartServer(addr)
	defer StopServer()
	
	v, err := internal.NewFakeAuthenticator(config.GetAuthKeyFile())
	if err != nil {
		t.Errorf("test CreateAuthValidator failed %v", err)
		return
	}
	_, err = CreateAuthValidator(v)
	if err != nil {
		t.Errorf("test CreateAuthValidator failed %v", err)
		return
	}

	_, err = CreateAuthValidator(v)
	if err != nil {
		t.Errorf("test CreateAuthValidator failed %v", err)
		return
	}
	
}

func TestNewClient(t *testing.T){
	

	server1 :="http://localhost:40009" 
	opt1 := WithHTTPClient(http.DefaultClient)
	opt2 := WithRequestEditorFn(func(ctx context.Context, req *http.Request) error{
		_=ctx
		_=req
		return nil
	})
	clienttest,err := NewClient(server1)
	if err!=nil{
		t.Errorf("NewClient failed %v", err)
	}
	_,err = NewClient(server1,opt1,opt2)
	if err!=nil{
		t.Errorf("NewClient failed %v", err)
	}
	ctx1, cancel := context.WithTimeout(context.Background(), timeout)

	_,err = clienttest.GetConfig(ctx1)
	if err ==nil{
		t.Errorf("test NewClient failed %v", err)
	}	
	_,err = clienttest.PostConfig(ctx1)
	if err ==nil{
		t.Errorf("test NewClient failed %v", err)
	}
	defer cancel()
}

func TestNewClientWithResponses(t *testing.T){

	server1 :="http://localhost:40009"
	opt1 :=WithBaseURL("http://localhost:40009")
	
	clienttest, err := NewClientWithResponses(server1)
	if err!=nil{
		t.Errorf("test NewClient failed %v", err)
	}

	_,err = NewClientWithResponses("",opt1)
	if err!=nil{
		t.Errorf("test NewClient failed %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	clienttest.GetConfigWithResponse(ctx)
	clienttest.PostConfigWithResponse(ctx)
	defer cancel()

}

func TestServerInterface(t *testing.T){
	s := &ServerInterfaceWrapper{&MyRestAPIServer{}}

	createFiles()
	defer removeFiles()
	//config.InitFlags()
	config.LoadConfigs()
	config.InitializeAS()
	addr := config.GetRestPort()
	
	

	go StartServer(addr)
	defer StopServer()
	

	e := echo.New()

	req := httptest.NewRequest(echo.GET, "/", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	
	err := s.GetConfig(ctx)
	if err!=nil{
		t.Errorf("TestServerInterface failed %v", err)
	}



	var configJSON0 = `{"basevalue":"testvalue"}`

	
	req = httptest.NewRequest(echo.POST, "/", strings.NewReader(configJSON0))
	

	rec = httptest.NewRecorder()
	ctx = e.NewContext(req, rec)
	err = s.PostConfig(ctx)
	if err==nil{
		t.Errorf("TestServerInterface failed ")
	}
	assert.Equal(t, http.StatusOK, rec.Code)


	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	
	ctx = e.NewContext(req, rec)
	
	err = s.PostConfig(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}


