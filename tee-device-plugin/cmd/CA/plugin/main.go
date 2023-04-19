package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"flag"

	"github.com/fsnotify/fsnotify"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
	tee "gitee.com/openeuler/kunpengsecl/tee-device-plugin/internal"
)

var precision, healthInternal uint

func main() {
	flag.UintVar(&precision, "precision", 512, "minimum precision of memory allocation(KB)")
	flag.UintVar(&healthInternal, "internal", 60, "health check internal (s)")
	flag.Parse()

	log.Printf("Starting FS watcher file: %s", pluginapi.DevicePluginPath)
	watcher, err := tee.NewFSWatcher(pluginapi.DevicePluginPath)
	if err != nil {
		log.Println("Failed to created FS watcher:", err)
		os.Exit(1)
	}
	defer watcher.Close()

	log.Println("Starting OS watcher.")
	sigs := tee.NewOSWatcher(syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	restart := true
	var devicePlugin *tee.TeeDevicePlugin

loop:
	for {
		if restart {
			if devicePlugin != nil {
				devicePlugin.Stop()
			}

			devicePlugin, err = tee.NewTeeDevicePlugin(precision, healthInternal)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
			
			err = devicePlugin.Start();
			if err != nil {
				log.Println("Starting tee device plugin failed: ", err)
			} else {
				restart = false
			}
		}

		select {
		case event := <-watcher.Events:
			if event.Name == pluginapi.KubeletSocket && event.Op&fsnotify.Create == fsnotify.Create {
				log.Printf("Inotify: %s created, restarting.", pluginapi.KubeletSocket)
				restart = true
			}

		case err := <-watcher.Errors:
			log.Printf("Inotify: %s", err)

		case s := <-sigs:
			switch s {
			case syscall.SIGHUP:
				log.Println("Received SIGHUP, restarting.")
				restart = true
			default:
				log.Printf("Received signal \"%v\", shutting down.", s)
				devicePlugin.Stop()
				break loop
			}
		}
	}
}