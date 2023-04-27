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
 * Description: internal package for tee device plugin server
 */
package internal

import (
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"path"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	resourceName = "huawei.com/tee-ram"
	deviceSocket = "tee-ram.sock"

	mountHostVolume      = "/var/run/teecd.sock"
	mountContainerVolume = "/var/run/teecd.sock"
	mountReadOnly        = false

	deviceHostTeelogPath      = "/dev/teelog"
	deviceContainerTeelogPath = "/dev/teelog"
	deviceTeelogPermissions   = "rw"

	deviceHostNsClientPath      = "/dev/tc_ns_client"
	deviceContainerNsClientPath = "/dev/tc_ns_client"
	deviceNsClientPermissions   = "rw"

	defaultBlockSeconds = 5
)

// TeeDevicePlugin abstract the tee device plugin
type TeeDevicePlugin struct {
	devs         []*pluginapi.Device
	deviceSocket string
	healthCheck  uint
	grpcServer   *grpc.Server
	stopChan     chan interface{}
	healthChan   chan string
}

func internalCheck(v1, v2 uint) error {
	if v1 != 0 && math.MaxInt64/v1 < v2 {
		return fmt.Errorf("%d is too large", v1)
	}
	return nil
}

// NewTeeDevicePlugin initial a new tee device plugin
func NewTeeDevicePlugin(allocPrecision, internalSeconds uint) (*TeeDevicePlugin, error) {
	err := internalCheck(internalSeconds, uint(time.Second))
	if err != nil {
		return nil, fmt.Errorf("health check internal set failed: %s", err)
	}

	err = setAllocatePrecision(allocPrecision)
	if err != nil {
		return nil, err
	}

	devs, err := getTotalFakeTeeDevices()
	if err != nil {
		return nil, err
	}

	return &TeeDevicePlugin{
		devs:         devs,
		deviceSocket: pluginapi.DevicePluginPath + deviceSocket,
		healthCheck:  internalSeconds,
		grpcServer:   grpc.NewServer([]grpc.ServerOption{}...),
		stopChan:     make(chan interface{}),
		healthChan:   make(chan string),
	}, nil
}

// Clean the socket file
func (plugin *TeeDevicePlugin) cleanup() error {
	err := os.Remove(plugin.deviceSocket)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// Stop the gRPC server
func (plugin *TeeDevicePlugin) Stop() {
	if plugin.grpcServer != nil {
		log.Println("Stoping to server on ", plugin.deviceSocket)
		plugin.grpcServer.Stop()
	} else {
		log.Println("Stoping, but grpc server is nil")
	}

	close(plugin.stopChan)
	plugin.grpcServer = nil
	plugin.healthChan = nil
	plugin.stopChan = nil

	err := plugin.cleanup()
	if err != nil {
		log.Println("Clean sock file failed: ", err)
	}
}

// Dial establishes the gRPC communication with the registered device plugin.
func dial(unixSocketPath string, timeout time.Duration) (*grpc.ClientConn, error) {
	c, err := grpc.Dial(unixSocketPath, grpc.WithInsecure(), grpc.WithBlock(),
		grpc.WithTimeout(timeout),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr, timeout)
		}),
	)

	if err != nil {
		return nil, err
	}

	return c, nil
}

// Serve the gRPC server of the device plugin
func (plugin *TeeDevicePlugin) serve() error {
	err := plugin.cleanup()
	if err != nil {
		return err
	}

	sock, err := net.Listen("unix", plugin.deviceSocket)
	if err != nil {
		return err
	}

	pluginapi.RegisterDevicePluginServer(plugin.grpcServer, plugin)
	go plugin.grpcServer.Serve(sock)

	// Wait for server to start by launching a blocking connexion
	conn, err := dial(plugin.deviceSocket, defaultBlockSeconds*time.Second)
	if err != nil {
		return err
	}
	conn.Close()

	return nil
}

// Start the grpc server, health check, register
func (plugin *TeeDevicePlugin) Start() error {
	err := plugin.serve()
	if err != nil {
		log.Println("Start gRPC server failed: ", err)
		return err
	}
	log.Println("Start gRPC server on: ", plugin.deviceSocket)

	err = plugin.Register()
	if err != nil {
		log.Println("Registe device plugin failed: ", err)
		plugin.Stop()
		return err
	}
	log.Println("Registe device plugin success")

	if plugin.healthCheck > 0 {
		go plugin.startHealthCheck()
	}

	return nil
}

// Start go routine to heath check tee status, send chan only when health changes
func (plugin *TeeDevicePlugin) startHealthCheck() {
	log.Printf("Start health check every %d seconds\n", plugin.healthCheck)
	ticker := time.NewTicker(time.Duration(plugin.healthCheck) * time.Second)
	lastHealth := ""
	for {
		select {
		case <-ticker.C:
			var health string
			freeNum, err := getFreeFakeTeeDeviceNum()
			if err != nil {
				health = pluginapi.Unhealthy
			} else {
				health = pluginapi.Healthy
			}
			log.Printf("Health check: tee free memory unit [%d]", freeNum)

			if lastHealth != health {
				log.Printf("Health is changed: %s -> %s", lastHealth, health)
				plugin.healthChan <- health
			}
			lastHealth = health
		case <-plugin.stopChan:
			ticker.Stop()
			return
		}
	}
}

// Register tee device plugin with kubelet
func (plugin *TeeDevicePlugin) Register() error {
	conn, err := dial(pluginapi.KubeletSocket, defaultBlockSeconds*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pluginapi.NewRegistrationClient(conn)
	reqt := &pluginapi.RegisterRequest{
		Version:      pluginapi.Version,
		Endpoint:     path.Base(plugin.deviceSocket),
		ResourceName: resourceName,
	}

	_, err = client.Register(context.Background(), reqt)
	if err != nil {
		return err
	}
	return nil
}

// ListAndWatch send devices list to kubelet
func (plugin *TeeDevicePlugin) ListAndWatch(e *pluginapi.Empty, s pluginapi.DevicePlugin_ListAndWatchServer) error {
	log.Printf("ListAndWatch exposing fake tee devices: %d\n", len(plugin.devs))
	s.Send(&pluginapi.ListAndWatchResponse{Devices: plugin.devs})

	for {
		select {
		case <-plugin.stopChan:
			return nil
		case health := <-plugin.healthChan:
			for _, dev := range plugin.devs {
				dev.Health = health
			}
			s.Send(&pluginapi.ListAndWatchResponse{Devices: plugin.devs})
		}
	}
}

// Allocate return mounts, devices to kubelet
func (plugin *TeeDevicePlugin) Allocate(ctx context.Context,
	reqs *pluginapi.AllocateRequest) (*pluginapi.AllocateResponse, error) {
	log.Println("Allocate request:", reqs.ContainerRequests)
	var neededNum uint64 = 0
	for _, req := range reqs.ContainerRequests {
		neededNum += uint64(len(req.DevicesIDs))
	}

	freeNum, err := getFreeFakeTeeDeviceNum()
	if err != nil {
		log.Println("Allocate memory failed: ", err)
		return nil, err
	}
	if freeNum < neededNum {
		log.Printf("Allocate memory failed: free memory %d, needed memory %d", freeNum, neededNum)
		return nil, fmt.Errorf("free memory is not enough")
	}

	mounts := []*pluginapi.Mount{
		&pluginapi.Mount{
			ContainerPath: mountContainerVolume,
			HostPath:      mountHostVolume,
			ReadOnly:      mountReadOnly,
		},
	}
	devices := []*pluginapi.DeviceSpec{
		&pluginapi.DeviceSpec{
			ContainerPath: deviceContainerTeelogPath,
			HostPath:      deviceHostTeelogPath,
			Permissions:   deviceTeelogPermissions,
		},
		&pluginapi.DeviceSpec{
			ContainerPath: deviceContainerNsClientPath,
			HostPath:      deviceHostNsClientPath,
			Permissions:   deviceNsClientPermissions,
		},
	}

	responses := pluginapi.AllocateResponse{}
	for _, _ = range reqs.ContainerRequests {
		resp := &pluginapi.ContainerAllocateResponse{
			Mounts:  mounts,
			Devices: devices,
		}
		responses.ContainerResponses = append(responses.ContainerResponses, resp)
	}

	return &responses, nil
}

// GetDevicePluginOptions returns the options to be communicated with device plugin
func (plugin *TeeDevicePlugin) GetDevicePluginOptions(context.Context,
	*pluginapi.Empty) (*pluginapi.DevicePluginOptions, error) {
	return &pluginapi.DevicePluginOptions{
		PreStartRequired: false,
	}, nil
}

// PreStartContainer called before each container start
func (plugin *TeeDevicePlugin) PreStartContainer(context.Context,
	*pluginapi.PreStartContainerRequest) (*pluginapi.PreStartContainerResponse, error) {
	return &pluginapi.PreStartContainerResponse{}, nil
}

// GetPreferredAllocation returns a preferred set of devices to allocate
func (plugin *TeeDevicePlugin) GetPreferredAllocation(context.Context,
	*pluginapi.PreferredAllocationRequest) (*pluginapi.PreferredAllocationResponse, error) {
	return &pluginapi.PreferredAllocationResponse{}, nil
}
