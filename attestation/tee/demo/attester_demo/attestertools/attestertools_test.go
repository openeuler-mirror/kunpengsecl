/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wangli
Create: 2022-05-01
Description: invoke attester lib and get info from qapi
*/

package attestertools

import (
	"io/ioutil"
	"os"
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qapi"
	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qcatools"
)

const (
	ConfigPath = "./config.yaml"
	QcaConfig  = `
qcaconfig:
  server: 127.0.0.1:40007
  akserver: 127.0.0.1:40008
  scenario: 0
  nodaaacfile: ./nodaa-ac.crt
  daaacfile: ./daa-ac.crt
`
)

const (
	attesterCfg = `
attesterconfig:
  server: 127.0.0.1:40007
  basevalue: "./basevalue.txt"
  mspolicy: 2
  uuid: f68fd704-6eb1-4d14-b218-722850eb3ef0
`
	basevaluePath = "./basevalue.txt"
	basevalue     = `
AAA19DC2-13CD-5A40-99F9-06343DFBE691 FB4C924ECCE3D00021C97D7FE815F9400AFF90FB84D8A92651CDE3CA2AEB60B1 09972A4984CC521651B683B5C85DD9012104A9A57B165B3E26A7A237B7951AD0
C29D01B0-CD13-405A-99F9-06343DFBE691 090B10A2DF8CDBDB10509615C83F447F35579D2FE1C632C06BD8CA8C74D069F5 0F195258B87028A62FB29B1E9EF221897530DC090994E3B17B2350117D259492
f68fd704-6eb1-4d14-b218-722850eb3ef0 bda93201babc6ee96b60edd6b4104c0a5b2ab66f22b3e82a0fbe121c955755b2 319964db5bfad8ffd1b32abe7148f7681b1ef15f4bab8a20d377d9623feb3758		
`
)

func createQcaConfigFile() {
	ioutil.WriteFile(ConfigPath, []byte(QcaConfig), 0644)
}

func createAttesterConfigFile() {
	ioutil.WriteFile(ConfigPath, []byte(attesterCfg), 0644)
}

func createBaseValueFile() {
	ioutil.WriteFile(basevaluePath, []byte(basevalue), 0644)
}

func deleteConfigFile() {
	os.Remove(ConfigPath)
}

func deleteBaseValueFile() {
	os.Remove(basevaluePath)
}

func TestAttester(t *testing.T) {
	_ = t
	createQcaConfigFile()
	qcatools.LoadConfigs()
	go qapi.StartServer()
	defer qapi.StopServer()
	deleteConfigFile()

	createAttesterConfigFile()
	defer deleteConfigFile()
	createBaseValueFile()
	defer deleteBaseValueFile()
	InitFlags()
	LoadConfigs()
	test := true
	TestFlag = &test
	HandleFlags()
	StartAttester()
}
