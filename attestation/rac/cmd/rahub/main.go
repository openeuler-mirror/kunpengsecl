/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: gwei3
Create: 2021-09-17
Description: rahub communicates between ras and raagent.
*/

// rahub main package.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
)

const (
	rahubVersion = "version 1.1.0"
)

// signalHandler handles the singal and save configurations.
func signalHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		saveConfigs()
		os.Exit(0)
	}()
}

func handleFlags() {
	if versionFlag != nil && *versionFlag {
		fmt.Printf("rahub: %s\n", rahubVersion)
		os.Exit(0)
	}
	// init logger
	if verboseFlag != nil && *verboseFlag {
		logger.NewDebugLogger(GetLogPath())
	} else {
		logger.NewInfoLogger(GetLogPath())
	}
	// set command line input
	if server != nil && *server != "" {
		hubCfg.server = *server
	}
	if port != nil && *port != "" {
		hubCfg.port = *port
	}
}

func main() {
	initFlags()
	loadConfigs()
	handleFlags()
	signalHandler()

	clientapi.StartRaHub(GetPort(), GetServer())
}
