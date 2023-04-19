package internal

import (
	"time"
	"log"
	"os"
	"net"
	"path"
	"fmt"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)


const (
	resourceName				= "huawei.com/tee-ram"
	deviceSocket				= "tee-ram.sock"

	mountHostVolume				= "/var/run/teecd.sock"
	mountContainerVolume		= "/var/run/teecd.sock"
	mountReadOnly				= false
	
	deviceHostTeelogPath		= "/dev/teelog"
	deviceContainerTeelogPath	= "/dev/teelog"
	deviceTeelogPermissions		= "rw"

	deviceHostNsClientPath		= "/dev/tc_ns_client"
	deviceContainerNsClientPath	= "/dev/tc_ns_client"
	deviceNsClientPermissions	= "rw"
)

type TeeDevicePlugin struct {
	devs			[]*pluginapi.Device
	deviceSocket	string
	healthCheck		uint
	grpcServer		*grpc.Server
	stopChan		chan interface{}
	healthChan		chan string
}

func NewTeeDevicePlugin(allocPrecision, internalSeconds uint) (*TeeDevicePlugin, error) {
	err := setAllocatePrecision(allocPrecision)
	if err != nil {
		return nil, err
	}

	devs, err := getTotalFakeTeeDevices()
	if err != nil {
		return nil, err
	}

	return &TeeDevicePlugin {
		devs:			devs,
		deviceSocket:	pluginapi.DevicePluginPath + deviceSocket,
		healthCheck:	internalSeconds,
		grpcServer:		grpc.NewServer([]grpc.ServerOption{}...),
		stopChan:		make(chan interface{}),
		healthChan:		make(chan string),
	}, nil
}

// clean the socket file
func (plugin *TeeDevicePlugin) cleanup() error {
	err := os.Remove(plugin.deviceSocket)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// stop the gRPC server
func (plugin *TeeDevicePlugin) Stop() error {
	if plugin.grpcServer == nil {
		return nil
	}

	log.Printf("Stoping to server on %s\n", plugin.deviceSocket)
	plugin.grpcServer.Stop()

	close(plugin.stopChan)
	plugin.grpcServer = nil
	plugin.healthChan = nil
	plugin.stopChan = nil
	
	return plugin.cleanup()
}

// dial establishes the gRPC communication with the registered device plugin.
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
	conn, err := dial(plugin.deviceSocket, 5*time.Second)
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
		log.Printf("Start gRPC server failed: %s\n", err)
		return err
	}
	log.Printf("Start gRPC server on: %s\n", plugin.deviceSocket)

	err = plugin.Register()
	if err != nil {
		log.Printf("Registe device plugin failed: %s\n", err)
		plugin.Stop()
		return err
	}
	log.Printf("Registe device plugin success")

	if plugin.healthCheck > 0 {
		go plugin.startHealthCheck()
	}

	return nil
}

// start go routine to heath check tee status, send chan only when health changes
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

// register device plugin with kubelet
func (plugin *TeeDevicePlugin) Register() error {
	conn, err := dial(pluginapi.KubeletSocket, 5*time.Second)
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

// send devices list to kubelet
func (plugin *TeeDevicePlugin) ListAndWatch(e *pluginapi.Empty, s pluginapi.DevicePlugin_ListAndWatchServer) error {
	log.Printf("ListAndWatch exposing fake tee %d devices: ", len(plugin.devs))
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

// return mounts and devices
func (plugin *TeeDevicePlugin) Allocate(ctx context.Context, reqs *pluginapi.AllocateRequest) (*pluginapi.AllocateResponse, error) {
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
		return nil, fmt.Errorf("Free memory is not enough")
	}

	mounts := []*pluginapi.Mount{
		&pluginapi.Mount{
			ContainerPath: 	mountContainerVolume,
			HostPath:		mountHostVolume,
			ReadOnly:		mountReadOnly,
		},
	}
	devices := []*pluginapi.DeviceSpec{
		&pluginapi.DeviceSpec{
			ContainerPath:	deviceContainerTeelogPath,
			HostPath:		deviceHostTeelogPath,
			Permissions:	deviceTeelogPermissions,
		},
		&pluginapi.DeviceSpec{
			ContainerPath:	deviceContainerNsClientPath,
			HostPath:		deviceHostNsClientPath,
			Permissions:	deviceNsClientPermissions,
		},
	}

	responses := pluginapi.AllocateResponse{}
	for _, _ = range reqs.ContainerRequests {
		resp := &pluginapi.ContainerAllocateResponse {
			Mounts: mounts,
			Devices: devices,
		}
		responses.ContainerResponses = append(responses.ContainerResponses, resp)
	}

	return &responses, nil
}

func (plugin *TeeDevicePlugin) GetDevicePluginOptions(context.Context, *pluginapi.Empty) (*pluginapi.DevicePluginOptions, error) {
	return &pluginapi.DevicePluginOptions{
		PreStartRequired: false,
	}, nil
}

func (plugin *TeeDevicePlugin) PreStartContainer(context.Context, *pluginapi.PreStartContainerRequest) (*pluginapi.PreStartContainerResponse, error) {
	return &pluginapi.PreStartContainerResponse{}, nil
}

func (plugin *TeeDevicePlugin) GetPreferredAllocation(context.Context, *pluginapi.PreferredAllocationRequest) (*pluginapi.PreferredAllocationResponse, error) {
	return &pluginapi.PreferredAllocationResponse{}, nil
}
