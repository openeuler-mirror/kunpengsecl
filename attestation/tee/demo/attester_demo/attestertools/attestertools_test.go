package attestertools

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
	"time"
)

const attesterCfg = `
attesterconfig:
  server: 127.0.0.1:40001
  basevalue: "../../../tverlib/verifier/basevalue.txt"
  mspolicy: 1
  uuid: 1
  scenario: 0
`

const (
	configFilePath = "./config.yaml"
)

func createConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(attesterCfg), 0644)
}

func deleteConfigFile() {
	_ = os.RemoveAll(configFilePath)
}

func server(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	con, err := lis.Accept()
	if err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	defer con.Close()
	return nil
}

func TestAttester(t *testing.T) {
	createConfigFile()
	defer deleteConfigFile()
	LoadConfigs()

	go StartAttester()

	err := server(attesterConf.server)
	if err != nil {
		t.Errorf("Start Server failed.")
	}
}
