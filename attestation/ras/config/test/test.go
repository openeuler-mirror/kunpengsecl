package test

import (
	"io/ioutil"
	"os"
)

const clientConfig = `conftype: client
racconfig:
  server: 127.0.0.1:40001
  hbduration: 5s
  trustduration: 2m0s
  clientId: -1
  password: ""
  digestalgorithm: sha256
`

const hubConfig = `conftype: hub
hubconfig:
  server: 127.0.0.1:40001
  hubport: "127.0.0.1:40003"
`

const serverConfig = `conftype: server
database:
  host: localhost
  dbname: kunpengsecl
  port: 5432
  user: "postgres"
  password: "postgres"
rasconfig:
  port: "127.0.0.1:40001"
  rest: "127.0.0.1:40002"
  changetime: 0
  mgrstrategy: auto
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
