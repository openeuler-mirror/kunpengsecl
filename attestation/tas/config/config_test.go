package config

import (
	"io/ioutil"
	"os"
	"testing"
)

const (
	testString1 = "cc0fe80b4510b3c8d5bf6308024676d2d9e83fbb05ba3d23cd645bfb573ae8a1 bd9df1a7f941c572c14723b80a0fbd805d52641bbac8325681a19d8ba8487b53"
	testString2 = "*%$****(^$#@@)@%^(&$@@&*((*^@!()_)+&*_*_^%$#&^*^&$#@!#$%^&*(()&* !@#$@$#!$&^&*)*__*&%)$%^&*_)*&&)(&%$#$&^(*&)&%@@!#$%^&)(*&^%*(&)"
	testString3 = "0000000000000000000000000000000000000000000000000000000000000000 0000000000000000000000000000000000000000000000000000000000000000"
)

const serverConfig = `
tasconfig:
  port: 127.0.0.1:40008
  rest: 127.0.0.1:40009
  akskeycertfile: ../cmd/ascert.crt
  aksprivkeyfile: ../cmd/aspriv.key
  huaweiitcafile: ../cmd/Huawei IT Product CA.pem
  DAA_GRP_KEY_SK_X: 65A9BF91AC8832379FF04DD2C6DEF16D48A56BE244F6E19274E97881A776543C
  DAA_GRP_KEY_SK_Y: 126F74258BB0CECA2AE7522C51825F980549EC1EF24F81D189D17E38F1773B56
  basevalue: ""
  authkeyfile: ../cmd/ecdsakey.pub
`

const configFilePath = "./config.yaml"

var (
	testCases = []struct {
		input  string
		result string
	}{
		{testString1, testString1},
		{testString2, testString2},
		{testString3, testString3},
	}
)

func CreateServerConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(serverConfig), 0644)
}

func RemoveConfigFile() {
	os.Remove(configFilePath)
}

func TestConfig(t *testing.T) {
	CreateServerConfigFile()
	defer RemoveConfigFile()

	InitFlags()
	LoadConfigs()
	InitializeAS()

	if cfg := GetConfigs(); cfg == nil {
		t.Error("get tas config error")
	}
	if serv := GetServerPort(); serv != "127.0.0.1:40008" {
		t.Error("get clientapi addr error")
	}
	if rest := GetRestPort(); rest != "127.0.0.1:40009" {
		t.Error("get restapi addr error")
	}
	if acfile := GetASCertFile(); acfile != "../cmd/ascert.crt" {
		t.Error("get as cert file path error")
	}
	if akfile := GetASKeyFile(); akfile != "../cmd/aspriv.key" {
		t.Error("get as key file path error")
	}
	if hwfile := GetHWCertFile(); hwfile != "../cmd/Huawei IT Product CA.pem" {
		t.Error("get huawei cert file path error")
	}
	if ascert := GetASCert(); ascert == nil {
		t.Error("get as cert error")
	}
	if aspriv := GetASPrivKey(); aspriv == nil {
		t.Error("get as privkey error")
	}
	if hwcert := GetHWCert(); hwcert == nil {
		t.Error("get huawei cert error")
	}
	if DAA_X, DAA_Y := GetDAAGrpPrivKey(); DAA_X != "65A9BF91AC8832379FF04DD2C6DEF16D48A56BE244F6E19274E97881A776543C" &&
		DAA_Y != "126F74258BB0CECA2AE7522C51825F980549EC1EF24F81D189D17E38F1773B56" {
		t.Error("get daa privkey error")
	}
	if authfile := GetAuthKeyFile(); authfile != "../cmd/ecdsakey.pub" {
		t.Error("get authkey file error")
	}
	for i := 0; i < len(testCases); i++ {
		SetBaseValue(testCases[i].input)
		if GetBaseValue() != testCases[i].result {
			t.Errorf("test basevalue error at case %d\n", i)
		}
	}
}
