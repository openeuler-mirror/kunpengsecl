/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 *
 * kunpengsecl licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of
 * the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author: chenzheng
 * Create: 2023-04-23
 * Description: main package for tee device plugin
 */
package main

import (
	"flag"
	"log"
	"os"
	"syscall"

	tee "gitee.com/openeuler/kunpengsecl/tee-device-plugin/internal"
	"github.com/fsnotify/fsnotify"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

var precision, healthInternal uint

const (
	defaultPrecision = 512
	defaultInternal  = 60
)

var (
	devicePlugin *tee.TeeDevicePlugin
	watcher      *fsnotify.Watcher
	sigs         chan os.Signal
)

func watch() bool {
	var err error

	log.Printf("Starting FS watcher file: %s", pluginapi.DevicePluginPath)
	watcher, err = tee.NewFSWatcher(pluginapi.DevicePluginPath)
	if err != nil {
		log.Println("Failed to created FS watcher:", err)
		log.Println("Exit.......")
		return true
	}

	log.Println("Starting OS watcher.")
	sigs = tee.NewOSWatcher(syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	return false
}

func restartPlugin(restart *bool) bool {
	var err error

	if devicePlugin != nil {
		devicePlugin.Stop()
	}

	devicePlugin, err = tee.NewTeeDevicePlugin(precision, healthInternal)
	if err != nil {
		log.Println("New tee device plugin failed: ", err)
		log.Println("Exit.......")
		return true
	}

	err = devicePlugin.Start()
	if err != nil {
		log.Println("Starting tee device plugin failed: ", err)
		log.Println("Restarting device plugin.......")
	} else {
		*restart = false
	}

	return false
}

func dealSignal(restart *bool) bool {
	select {
	case event := <-watcher.Events:
		if event.Name == pluginapi.KubeletSocket && event.Op&fsnotify.Create == fsnotify.Create {
			log.Printf("File %s created, kubelet restarted", pluginapi.KubeletSocket)
			log.Println("Restarting device plugin.......")
			*restart = true
		}

	case err := <-watcher.Errors:
		log.Printf("Watch error: %s", err)

	case s := <-sigs:
		switch s {
		case syscall.SIGHUP:
			log.Println("Received SIGHUP, restarting.")
			*restart = true
		default:
			log.Printf("Received signal [%v], shutting down.", s)
			devicePlugin.Stop()
			devicePlugin = nil
			log.Println("Exit.......")
			return true
		}
	}

	return false
}

func main() {
	flag.UintVar(&precision, "precision", defaultPrecision, "minimum precision of memory allocation(KB)")
	flag.UintVar(&healthInternal, "internal", defaultInternal, "health check internal (s)")
	flag.Parse()

	if exit := watch(); exit {
		os.Exit(1)
	}

	restart := true
	for {
		if restart {
			if exit := restartPlugin(&restart); exit {
				watcher.Close()
				os.Exit(1)
			}
		}

		if exit := dealSignal(&restart); exit {
			watcher.Close()
			os.Exit(1)
		}
	}
}
