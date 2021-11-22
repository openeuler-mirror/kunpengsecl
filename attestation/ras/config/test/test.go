package test

import (
	"io/ioutil"
	"os"
)

const testConfig = `conftype: server
database:
  dbname: kunpengsecl
  host: localhost
  password: "postgres"
  port: 5432
  user: "postgres"
racconfig:
  hbduration: 3s
  trustduration: 2m0s
rasconfig:
  changetime: 2021-09-30T11:53:24.0581136+08:00
  mgrstrategy: auto
  basevalue-extract-rules:
    pcrinfo:
      pcrselection: [1, 2, 3, 4]
    manifest:
      -
        type: bios
        name: ["name1", "name2"]
      -
        type: ima
        name: ["name1", "name2"] 
`
const configFilePath = "./config.yaml"

func CreateConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(testConfig), 0644)
}

func RemoveConfigFile() {
	os.Remove(configFilePath)
}
