package main

import (
	"io"
	"log"
	"os"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_daemon/daemontools"
)

const (
	LOG_FILE      = "./qca_daemon.log"
	LOG_FILE_MODE = 0600
)

func main() {
	logFile, err := os.OpenFile(LOG_FILE, os.O_CREATE|os.O_WRONLY, LOG_FILE_MODE)
	if err != nil {
		log.Fatalf("Open log file failed, %v\n", err)
	}
	defer func() {
		if err = logFile.Close(); err != nil {
			log.Fatalf("Close log file failed, %v\n", err)
		}
	}()

	log.SetOutput(io.MultiWriter(logFile, os.Stdout))

	flags := daemontools.InitFlags()
	info, err := daemontools.GetVirtualClientInfo()
	if err != nil {
		log.Fatalf("get virtual os info failed, %v", err)
	}

	daemontools.StartClientConn(flags.Hostserver, info)
}
