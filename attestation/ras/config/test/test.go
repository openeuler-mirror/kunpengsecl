package test

import (
	"io/ioutil"
	"os"
)

const clientConfig = `
racconfig:
  ikpkey: ""
  ikcert: ""
  ekpkeytest: ""
  ekcerttest: ""
  ikpkeytest: ""
  ikcerttest: ""
  server: 127.0.0.1:40001
  hbduration: 5s
  trustduration: 2m0s
  clientId: -1
  password: ""
  digestalgorithm: sha256
`

const hubConfig = `
hubconfig:
  server: 127.0.0.1:40001
  hubport: "127.0.0.1:40003"
`

const serverConfig = `
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
  mgrstrategy: auto
  authkeyfile: ./ecdsakey.pub
  basevalue-extract-rules:
    pcrinfo:
      pcrselection: [1, 2, 3, 4]
    manifest:
      - type: bios
        name: ["8-0", "2147483656-1"]
      - type: ima
        name: ["boot_aggregate", "/etc/modprobe.d/tuned.conf"]
  auto-update-config:
    isAllUpdate: false
    update-clients: [1, 2, 3]
racconfig:
  hbduration: 5s
  trustduration: 2m0s
  digestalgorithm: sha256
`
const configFilePath = "./config.yaml"

func CreateClientConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(clientConfig), 0644)
}

func CreateHubConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(hubConfig), 0644)
}

func CreateServerConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(serverConfig), 0644)
}

func RemoveConfigFile() {
	os.Remove(configFilePath)
}
