package attestertools

import (
	"io/ioutil"
	"net"
	"os"
	"testing"
)

const attesterCfg = `
attesterconfig:
  server: 127.0.0.1:40001
  basevalue: ""
  mspolicy: 2
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

func TestAttester(t *testing.T) {
	createConfigFile()
	defer deleteConfigFile()
	LoadConfigs()

	lis, err := net.Listen("tcp", attesterConf.server)
	if err != nil {
		t.Errorf("Listen %s failed, err: %v\n", attesterConf.server, err)
	}
	go StartAttester()

	con, err := lis.Accept()
	if err != nil {
		t.Errorf("Accept connection failed: %v", err)
	}
	defer con.Close()
}
