package restapi

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/internal"
	resttest "gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/verifier"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testExtractor struct {
}

var (
	authKeyFile    = "./ecdsakey"
	authKeyPubFile = "./ecdsakey.pub"
)

func (tv *testExtractor) Extract(report *entity.Report, mInfo *entity.MeasurementInfo) error {
	mInfo.ClientID = report.ClientID
	mInfo.PcrInfo = report.PcrInfo
	for _, mf := range report.Manifest {
		for _, mi := range mf.Items {
			mInfo.Manifest = append(mInfo.Manifest, entity.Measurement{
				Type:  mf.Type,
				Name:  mi.Name,
				Value: mi.Value,
			})
		}
	}
	return nil
}

func CreateServer(t *testing.T) {
	var addr = "127.0.0.1:5098"
	vm, err := verifier.CreateVerifierMgr()
	require.NoError(t, err)
	cm := cache.CreateCacheMgr(100, vm)

	StartServer(addr, cm)
}

func AddAuthReqEditor(jws string) RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		_ = ctx
		req.Header.Set("Authorization", "Bearer "+jws)
		return nil
	}
}

func CreateClient(t *testing.T) {
	c, _ := NewClientWithResponses("http://127.0.0.1:5098")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	v, err := internal.NewFakeAuthenticator(authKeyFile)
	require.NoError(t, err)

	// create a JWT with no scopes.
	emptyJWT, err := v.CreateJWSWithClaims([]string{})
	require.NoError(t, err)
	t.Logf("empty jwt: %s", string(emptyJWT))

	// create a JWT with write permission to config.
	writeJWT, err := v.CreateJWSWithClaims([]string{"write:config"})
	require.NoError(t, err)
	t.Logf("write jwt: %s", string(writeJWT))

	name := "version"
	value := "0.1.0"
	body := PostConfigJSONRequestBody{{&name, &value}}
	configResponse, err := c.GetConfigWithResponse(ctx)
	require.NoError(t, err)
	//	assert.Equal(t, http.StatusForbidden, configResponse.StatusCode())
	assert.Equal(t, http.StatusOK, configResponse.StatusCode())

	configResponse, err = c.GetConfigWithResponse(ctx, AddAuthReqEditor(string(emptyJWT)))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, configResponse.StatusCode())

	configResponse1, err := c.PostConfigWithResponse(ctx, body, AddAuthReqEditor(string(emptyJWT)))
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, configResponse1.StatusCode())

	configResponse1, err = c.PostConfigWithResponse(ctx, body, AddAuthReqEditor(string(writeJWT)))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, configResponse1.StatusCode())
}

func TestRestAPI(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	config.InitRasFlags()

	resttest.CreateAuthKeyFile(authKeyFile, authKeyPubFile)
	defer resttest.RemoveAuthKeyFile()

	t.Log("restapi created server")
	go CreateServer(t)
	time.Sleep(time.Duration(5) * time.Second)
	t.Log("restapi created client")
	CreateClient(t)
}

func TestGetConfig(t *testing.T) {
	t.Log("Get config as follows:")
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := NewRasServer(nil)
	err := s.GetConfig(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body)
	}
}

func TestPostConfig(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	var configJSON0 = `[{"name":"digestAlgorithm","value":"sha256"},{"name":"autoUpdateConfig","value":"{\"IsAllUpdate\":false,\"UpdateClients\":null}"},{"name":"dbPort","value":"5432"},{"name":"mgrStrategy","value":"auto"},{"name":"changeTime","value":"1970-01-01 08:00:00 +0800 CST"},{"name":"extractRules","value":"{\"PcrRule\":{\"PcrSelection\":[1,2,3,4]},\"ManifestRules\":[{\"MType\":\"bios\",\"Name\":[\"name1\",\"name2\"]},{\"MType\":\"ima\",\"Name\":[\"name1\",\"name2\"]}]}"},{"name":"hbDuration","value":"5s"},{"name":"trustDuration","value":"2m0s"},{"name":"dbHost","value":"localhost"},{"name":"dbName","value":"kunpengsecl"},{"name":"dbUser","value":"postgres"}]`
	var configJSON1 = `[{"name":"port", "value":"1000"}]`
	var configJSON2 = ``
	e := echo.New()
	s := NewRasServer(nil)

	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(configJSON0))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	err := s.PostConfig(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}

	req = httptest.NewRequest(echo.POST, "/", strings.NewReader(configJSON1))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	ctx = e.NewContext(req, rec)
	err = s.PostConfig(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}

	req = httptest.NewRequest(echo.POST, "/", strings.NewReader(configJSON2))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	ctx = e.NewContext(req, rec)
	err = s.PostConfig(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestGetStatus(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s, _ := prepareServers(t)

	err := s.GetStatus(ctx)
	assert.NoError(t, err)
	result := []ServerTrustStatus{}
	err = json.Unmarshal(rec.Body.Bytes(), &result)
	assert.NoError(t, err)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, cache.STSTRUSTED, result[0].Status)
	}
}

func TestGetStatusById(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s, cid := prepareServers(t)

	err := s.GetStatusServerId(ctx, cid)
	assert.NoError(t, err)
	result := ServerTrustStatus{}
	err = json.Unmarshal(rec.Body.Bytes(), &result)
	assert.NoError(t, err)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, cache.STSTRUSTED, result.Status)
	}
}

func TestGetServer(t *testing.T) {
	t.Log("Get server:")
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ic := createRandomCert()
	clientInfo := entity.ClientInfo{
		Info: map[string]string{
			"client_name":        "test_client",
			"client_type":        "test_type",
			"client_description": "test description",
			"ip":                 "ip",
		},
	}
	_, err := trustmgr.RegisterClient(&clientInfo, ic)
	assert.NoError(t, err)
	s, _ := prepareServers(t)
	err = s.GetServer(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body.String())
		result := []ServerBriefInfo{}
		json.Unmarshal(rec.Body.Bytes(), &result)
		t.Log(result)
	}

}

func TestPutServer(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	s, _ := prepareServers(t)
	var serverJSON0 = `{"clientids":[1], "registered":false}`
	var serverJSON1 = `{"clientids":[1], "registered":true}`

	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(serverJSON0))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	err := s.PutServer(ctx)
	regClient, _ := trustmgr.GetRegisterClientById(1)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Logf("Get the current server registered status as follows:%v", !regClient.IsDeleted)
	}

	req = httptest.NewRequest(echo.POST, "/", strings.NewReader(serverJSON1))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	ctx = e.NewContext(req, rec)
	err = s.PutServer(ctx)
	regClient, _ = trustmgr.GetRegisterClientById(1)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Logf("Get the current server registered status as follows:%v", !regClient.IsDeleted)
	}
}

func TestGetServerBasevalue(t *testing.T) {
	t.Log("Get Server Basevalue by server id:")
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s, cid := prepareServers(t)
	err := s.GetServerBasevalueServerId(ctx, cid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log((rec.Body))
	}
}

func TestPutServerBasevalue(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	s, cid := prepareServers(t)
	var baseValueJSON0 = `{
		"measurements":[{
			"name":"mName",
			"type":"mType",
			"value":"mValue"
		}],
		"pcrvalues":[{
			"index":0,
			"value":"pValue0"
		}]
	}`
	var baseValueJSON1 = `{
		"measurements":[{
			"name":"mName1",
			"type":"mType1",
			"value":"mValue1"
		}],
		"pcrvalues":[{
			"index":1,
			"value":"pValue1"
		}]
	}`

	req := httptest.NewRequest(echo.PUT, "/", strings.NewReader(baseValueJSON0))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	err := s.PutServerBasevalueServerId(ctx, cid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}

	req = httptest.NewRequest(echo.PUT, "/", strings.NewReader(baseValueJSON1))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	ctx = e.NewContext(req, rec)
	err = s.PutServerBasevalueServerId(ctx, cid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestGetReportServerId(t *testing.T) {
	t.Log("Get server report:")
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	s, cid := prepareServers(t)

	err := s.GetReportServerId(ctx, cid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body)
	}
}

func TestGetContainer(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	s, cid := prepareServers(t)
	uuid := uuid.New().String()
	trustmgr.AddContainer(&entity.Container{
		UUID:     uuid,
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	})
	err := s.GetContainerUuid(ctx, uuid)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	result := entity.Container{}
	err = json.Unmarshal(rec.Body.Bytes(), &result)
	assert.NoError(t, err)
	assert.Equal(t, cid, result.ClientId)
}

func TestPostContainer(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	s, cid := prepareServers(t)
	uuid := uuid.New().String()
	e := echo.New()
	registered := true
	con := ContainerBriefInfo{
		Uuid:       &uuid,
		Serverid:   &cid,
		Registered: &registered,
	}
	j, err := json.Marshal(con)
	assert.NoError(t, err)
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(string(j)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	err = s.PostContainerUuid(ctx, uuid)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	con2, err := trustmgr.GetContainerByUUId(uuid)
	assert.NoError(t, err)
	assert.Equal(t, con2.ClientId, *con.Serverid)
}

func TestPutContainerUuid(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	s, cid := prepareServers(t)

	registered := false
	r, err := json.Marshal(registered)
	assert.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(echo.PUT, "/", strings.NewReader(string(r)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	uuid := uuid.New().String()
	trustmgr.AddContainer(&entity.Container{
		UUID:     uuid,
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	})
	c, err := trustmgr.GetContainerByUUId(uuid)
	assert.NoError(t, err)
	assert.Equal(t, false, c.Deleted)

	err = s.PutContainerUuid(ctx, uuid)
	assert.NoError(t, err)
	c, err = trustmgr.GetContainerByUUId(uuid)
	assert.NoError(t, err)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, true, c.Deleted)
	}
}

var testName1 = "name1"
var testName2 = "name2"
var testValue1 = "value1"
var testValue2 = "value2"
var testType = "ima"
var testBv = map[string]string{
	testName1: testValue1,
	testName2: testValue2,
}

var testMea = []Measurement{
	0: {
		Name:  &testName1,
		Value: &testValue1,
		Type:  (*MeasurementType)(&testType),
	},
	1: {
		Name:  &testName2,
		Value: &testValue2,
		Type:  (*MeasurementType)(&testType),
	},
}
var pcrValue1 = "pcr value1"
var pcrValue2 = "pcr value2"
var testPi = entity.PcrInfo{
	Values: map[int]string{
		1: pcrValue1,
		2: pcrValue2,
	},
}

var testRepMea = []entity.Measurement{
	0: {
		Type:  testType,
		Name:  testName1,
		Value: testValue1,
	},
	1: {
		Type:  testType,
		Name:  testName2,
		Value: testValue2,
	},
}

func TestGetContainerBasevalueUuid(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	s, cid := prepareServers(t)
	uuid := uuid.New().String()
	err := trustmgr.AddContainer(&entity.Container{
		UUID:     uuid,
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	})
	assert.NoError(t, err)
	err = trustmgr.AddContainerBaseValue(&entity.ContainerBaseValue{
		ContainerUUID: uuid,
		Value:         testBv,
	})
	assert.NoError(t, err)
	err = s.GetContainerBasevalueUuid(ctx, uuid)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	result := entity.ContainerBaseValue{}
	err = json.Unmarshal(rec.Body.Bytes(), &result)
	assert.NoError(t, err)
	assert.Equal(t, testBv, result.Value)
}

func TestPutContainerBasevalueUuid(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	s, cid := prepareServers(t)

	cbv := ContainerBaseValue{Measurements: &testMea}
	r, err := json.Marshal(cbv)
	assert.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(echo.PUT, "/", strings.NewReader(string(r)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	uuid := uuid.New().String()
	trustmgr.AddContainer(&entity.Container{
		UUID:     uuid,
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	})

	err = s.PutContainerBasevalueUuid(ctx, uuid)
	assert.NoError(t, err)
	b, err := trustmgr.GetContainerBaseValueByUUId(uuid)
	assert.NoError(t, err)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, *testMea[0].Value, b.Value[testName1])
	}
}

func TestGetContainerStatus(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	s, cid := prepareServers(t)
	uuid := uuid.New().String()
	trustmgr.AddContainer(&entity.Container{
		UUID:     uuid,
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	})
	trustmgr.AddContainerBaseValue(&entity.ContainerBaseValue{
		ContainerUUID: uuid,
		Value:         testBv,
	})
	testMf := entity.Manifest{
		Type: "ima",
		Items: []entity.ManifestItem{
			0: {
				Name:  testName1,
				Value: testValue1,
			},
			1: {
				Name:  testName2,
				Value: testValue2,
			},
		},
	}
	// sleep to sort
	time.Sleep(time.Second * 1)
	// record report and base value to test
	pi := entity.PcrInfo{
		Values: map[int]string{
			1: pcrValue1,
			2: pcrValue2,
		},
	}
	err := trustmgr.RecordReport(&entity.Report{
		PcrInfo:  pi,
		ClientID: cid,
		Manifest: []entity.Manifest{testMf},
	})
	assert.NoError(t, err)
	err = trustmgr.SaveBaseValueById(cid, &entity.MeasurementInfo{
		ClientID: cid,
		PcrInfo:  pi,
		Manifest: testRepMea,
	})
	assert.NoError(t, err)
	err = s.GetContainerStatus(ctx)
	tss := []ContainerTrustStatus{}
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	err = json.Unmarshal(rec.Body.Bytes(), &tss)
	assert.NoError(t, err)
	assert.Equal(t, cache.STSTRUSTED, tss[0].Status)
}

func TestGetContainerStatusUuId(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	s, cid := prepareServers(t)
	uuid := uuid.New().String()
	trustmgr.AddContainer(&entity.Container{
		UUID:     uuid,
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	})
	trustmgr.AddContainerBaseValue(&entity.ContainerBaseValue{
		ContainerUUID: uuid,
		Value:         testBv,
	})
	testMf := entity.Manifest{
		Type: "ima",
		Items: []entity.ManifestItem{
			0: {
				Name:  testName1,
				Value: testValue1,
			},
			1: {
				Name:  testName2,
				Value: testValue2,
			},
		},
	}
	// sleep to sort
	time.Sleep(time.Second * 1)
	// record report and base value to test
	pi := entity.PcrInfo{
		Values: map[int]string{
			1: pcrValue1,
			2: pcrValue2,
		},
	}
	err := trustmgr.RecordReport(&entity.Report{
		PcrInfo:  pi,
		ClientID: cid,
		Manifest: []entity.Manifest{testMf},
	})
	assert.NoError(t, err)
	err = trustmgr.SaveBaseValueById(cid, &entity.MeasurementInfo{
		ClientID: cid,
		PcrInfo:  pi,
		Manifest: testRepMea,
	})
	assert.NoError(t, err)
	err = s.GetContainerStatusUuid(ctx, uuid)
	ts := ContainerTrustStatus{}
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	err = json.Unmarshal(rec.Body.Bytes(), &ts)
	assert.NoError(t, err)
	assert.Equal(t, cache.STSTRUSTED, ts.Status)
}
func TestGetDevice(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	s, cid := prepareServers(t)

	rand.Seed(time.Now().UnixNano())
	deviceId := rand.Int31()
	trustmgr.AddDevice(&entity.PcieDevice{
		ID:       int64(deviceId),
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	})
	err := s.GetDeviceId(ctx, int64(deviceId))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	result := entity.PcieDevice{}
	err = json.Unmarshal(rec.Body.Bytes(), &result)
	assert.NoError(t, err)
	assert.Equal(t, cid, result.ClientId)
}

func TestPostDevice(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	s, cid := prepareServers(t)
	rand.Seed(time.Now().UnixNano())
	deviceId := int64(rand.Int31())
	e := echo.New()
	registered := true
	dev := DeviceBriefInfo{
		Id:         &deviceId,
		Serverid:   &cid,
		Registered: &registered,
	}
	j, err := json.Marshal(dev)
	assert.NoError(t, err)
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(string(j)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	err = s.PostDeviceId(ctx, deviceId)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	dev2, err := trustmgr.GetDeviceById(deviceId)
	assert.NoError(t, err)
	assert.Equal(t, dev2.ClientId, *dev.Serverid)
}

func TestPutDeviceId(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	s, cid := prepareServers(t)

	registered := false
	r, err := json.Marshal(registered)
	assert.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(echo.PUT, "/", strings.NewReader(string(r)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	rand.Seed(time.Now().UnixNano())
	deviceId := int64(rand.Int31())
	trustmgr.AddDevice(&entity.PcieDevice{
		ID:       deviceId,
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	})
	c, err := trustmgr.GetDeviceById(deviceId)
	assert.NoError(t, err)
	assert.Equal(t, false, c.Deleted)

	err = s.PutDeviceId(ctx, deviceId)
	assert.NoError(t, err)
	c, err = trustmgr.GetDeviceById(deviceId)
	assert.NoError(t, err)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, true, c.Deleted)
	}
}

func TestGetDeviceBasevalueUuid(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	s, cid := prepareServers(t)
	rand.Seed(time.Now().UnixNano())
	deviceId := int64(rand.Int31())
	err := trustmgr.AddDevice(&entity.PcieDevice{
		ID:       deviceId,
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	})
	assert.NoError(t, err)
	err = trustmgr.AddDeviceBaseValue(&entity.PcieBaseValue{
		DeviceID: deviceId,
		Value:    testBv,
	})
	assert.NoError(t, err)
	err = s.GetDeviceBasevalueId(ctx, deviceId)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	result := entity.PcieBaseValue{}
	err = json.Unmarshal(rec.Body.Bytes(), &result)
	assert.NoError(t, err)
	assert.Equal(t, testBv, result.Value)
}

func TestPutDeviceBasevalueUuid(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	s, cid := prepareServers(t)

	cbv := ContainerBaseValue{Measurements: &testMea}
	r, err := json.Marshal(cbv)
	assert.NoError(t, err)
	e := echo.New()
	req := httptest.NewRequest(echo.PUT, "/", strings.NewReader(string(r)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	rand.Seed(time.Now().UnixNano())
	deviceId := int64(rand.Int31())
	trustmgr.AddDevice(&entity.PcieDevice{
		ID:       deviceId,
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	})

	err = s.PutDeviceBasevalueId(ctx, deviceId)
	assert.NoError(t, err)
	b, err := trustmgr.GetDeviceBaseValueById(deviceId)
	assert.NoError(t, err)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, *testMea[0].Value, b.Value[testName1])
	}
}

func TestGetDeviceStatus(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	s, cid := prepareServers(t)
	rand.Seed(time.Now().UnixNano())
	deviceId := int64(rand.Int31())
	trustmgr.AddDevice(&entity.PcieDevice{
		ID:       deviceId,
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	})
	trustmgr.AddDeviceBaseValue(&entity.PcieBaseValue{
		DeviceID: deviceId,
		Value:    testBv,
	})
	testMf := entity.Manifest{
		Type: "ima",
		Items: []entity.ManifestItem{
			0: {
				Name:  testName1,
				Value: testValue1,
			},
			1: {
				Name:  testName2,
				Value: testValue2,
			},
		},
	}
	// sleep to sort
	time.Sleep(time.Second * 1)
	// record report and base value to test
	pi := entity.PcrInfo{
		Values: map[int]string{
			1: pcrValue1,
			2: pcrValue2,
		},
	}
	err := trustmgr.RecordReport(&entity.Report{
		PcrInfo:  pi,
		ClientID: cid,
		Manifest: []entity.Manifest{testMf},
	})
	assert.NoError(t, err)
	err = trustmgr.SaveBaseValueById(cid, &entity.MeasurementInfo{
		ClientID: cid,
		PcrInfo:  pi,
		Manifest: testRepMea,
	})
	assert.NoError(t, err)
	err = s.GetDeviceStatus(ctx)
	tss := []DeviceTrustStatus{}
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	err = json.Unmarshal(rec.Body.Bytes(), &tss)
	assert.NoError(t, err)
	assert.Equal(t, cache.STSTRUSTED, tss[0].Status)
}

func TestGetDeviceStatusId(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	s, cid := prepareServers(t)
	rand.Seed(time.Now().UnixNano())
	deviceId := int64(rand.Int31())
	trustmgr.AddDevice(&entity.PcieDevice{
		ID:       deviceId,
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	})
	trustmgr.AddDeviceBaseValue(&entity.PcieBaseValue{
		DeviceID: deviceId,
		Value:    testBv,
	})
	testMf := entity.Manifest{
		Type: "ima",
		Items: []entity.ManifestItem{
			0: {
				Name:  testName1,
				Value: testValue1,
			},
			1: {
				Name:  testName2,
				Value: testValue2,
			},
		},
	}
	// sleep to sort
	time.Sleep(time.Second * 1)
	// record report and base value to test
	pi := entity.PcrInfo{
		Values: map[int]string{
			1: pcrValue1,
			2: pcrValue2,
		},
	}
	err := trustmgr.RecordReport(&entity.Report{
		PcrInfo:  pi,
		ClientID: cid,
		Manifest: []entity.Manifest{testMf},
	})
	assert.NoError(t, err)
	err = trustmgr.SaveBaseValueById(cid, &entity.MeasurementInfo{
		ClientID: cid,
		PcrInfo:  pi,
		Manifest: testRepMea,
	})
	assert.NoError(t, err)
	err = s.GetDeviceStatusId(ctx, deviceId)
	ts := DeviceTrustStatus{}
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	err = json.Unmarshal(rec.Body.Bytes(), &ts)
	assert.NoError(t, err)
	assert.Equal(t, cache.STSTRUSTED, ts.Status)
}

func TestGetVersion(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	s := NewRasServer(nil)
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	err := s.GetVersion(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

type testValidator struct {
}

func (tv *testValidator) Validate(report *entity.Report) error {
	return nil
}

func createRandomCert() []byte {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	strBytes := []byte(str)
	randomCert := []byte{}
	ra := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 6; i++ {
		randomCert = append(randomCert, strBytes[ra.Intn(len(strBytes))])
	}
	return randomCert
}

func prepareServers(t *testing.T) (*RasServer, int64) {
	trustmgr.SetExtractor(&testExtractor{})
	vm, err := verifier.CreateVerifierMgr()
	require.NoError(t, err)
	cm := cache.CreateCacheMgr(cache.DEFAULTRACNUM, vm)
	s := NewRasServer(cm)
	sc := clientapi.NewServer(cm)

	ci, err := json.Marshal(map[string]string{"test name": "test value"})
	if err != nil {
		t.Error(err)
	}

	r, err := sc.RegisterClient(context.Background(),
		&clientapi.RegisterClientRequest{
			Ic:         &clientapi.Cert{Cert: createRandomCert()},
			ClientInfo: &clientapi.ClientInfo{ClientInfo: string(ci)},
		})
	if err != nil {
		t.Errorf("Client: invoke RegisterClient error %v", err)
	}
	t.Logf("Client: invoke RegisterClient ok, clientID=%d", r.GetClientId())
	cfg := config.GetDefault(config.ConfServer)
	trustmgr.SetValidator(&testValidator{})
	_, err = sc.SendReport(context.Background(),
		&clientapi.SendReportRequest{
			ClientId: r.GetClientId(),
			TrustReport: &clientapi.TrustReport{
				PcrInfo: &clientapi.PcrInfo{
					PcrValues: map[int32]string{
						1: pcrValue1,
						2: pcrValue2,
					},
					PcrQuote: &clientapi.PcrQuote{
						Quoted: []byte("test quote"),
					},
					Algorithm: cfg.GetDigestAlgorithm(),
				},
				Manifest: []*clientapi.Manifest{},
				ClientId: r.GetClientId(),
			}})
	if err != nil {
		t.Errorf("Client: invoke SendReport error %v", err)
	}
	t.Logf("Client: invoke SendReport ok")

	return s, r.GetClientId()
}

func TestCreateTestAuthToken(t *testing.T) {
	token, err := CreateTestAuthToken()
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log(token)
}
