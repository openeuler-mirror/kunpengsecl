package internal
/*
#cgo CFLAGS: -I../cmd/CA/libteememca
#cgo LDFLAGS: -L../cmd/CA/libteememca -lteememca -ldl
#include "tee_mem_ca.h"
*/
import "C"
import (
	"log"
	"fmt"

	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

var allocPrecision uint = 512
const maxFakeTeeDevicesNum = 220000

func setAllocatePrecision(precision uint) error {
	if precision < allocPrecision {
		fmt.Errorf("Allocate precision should >= %d KB\n", allocPrecision)
	}
	allocPrecision = precision
	log.Printf("Set allocate memory precision: %d KB\n", allocPrecision)

	return nil
}

func getFreeFakeTeeDeviceNum() (uint64, error) {
	freeMem := int64(C.GetTeeFreeMem())
	if freeMem == -1 {
		return 0, fmt.Errorf("Get Tee free memory failed.")
	}

	return uint64(freeMem) / uint64(allocPrecision), nil
}

func getTotalFakeTeeDevices() ([]*pluginapi.Device, error) {
	capacity := int64(C.GetTeeCapacityMem())
	if capacity == -1 {
		return nil, fmt.Errorf("Get Tee capacity memory failed.")
	}

	deviceNum := capacity / int64(allocPrecision)
	if deviceNum < 1 {
		return nil, fmt.Errorf("Decrease precision, precision should less than tee capacity memory %d", capacity)
	} else if deviceNum > maxFakeTeeDevicesNum {
		return nil, fmt.Errorf("Increase precision, max fake device number should less than %d", maxFakeTeeDevicesNum)
	}

	var devs = make([]*pluginapi.Device, deviceNum)
	for i, _ := range devs {
		devs[i] = &pluginapi.Device {
			ID: fmt.Sprint(i),
			Health: pluginapi.Healthy,
		}
	}

	return devs, nil
}