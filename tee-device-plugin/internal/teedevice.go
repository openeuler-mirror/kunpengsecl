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
 * Description: internal package for get tee memory by CA/TA connection
 */
package internal

/*
#cgo CFLAGS: -I../cmd/CA/libteememca
#cgo LDFLAGS: -L../cmd/CA/libteememca -lteememca -ldl
#include "tee_mem_ca.h"
*/
import "C"
import (
	"fmt"
	"log"

	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	maxFakeTeeDevicesNum = 220000
	minPrecision         = 512
)

var allocPrecision uint

func setAllocatePrecision(precision uint) error {
	if precision < minPrecision {
		return fmt.Errorf("allocate precision should greater than %d KB", minPrecision)
	}

	allocPrecision = precision
	log.Printf("Set allocate memory precision: %d KB\n", allocPrecision)

	return nil
}

func getFreeFakeTeeDeviceNum() (uint64, error) {
	freeMem := int64(C.GetTeeFreeMem())
	if freeMem == -1 {
		return 0, fmt.Errorf("get tee free memory failed")
	}

	return uint64(freeMem) / uint64(allocPrecision), nil
}

func getTotalFakeTeeDevices() ([]*pluginapi.Device, error) {
	capacity := int64(C.GetTeeCapacityMem())
	if capacity == -1 {
		return nil, fmt.Errorf("get tee capacity memory failed")
	}

	deviceNum := capacity / int64(allocPrecision)
	if deviceNum < 1 {
		return nil, fmt.Errorf("decrease precision, precision should less than tee capacity memory %d", capacity)
	} else if deviceNum > maxFakeTeeDevicesNum {
		return nil, fmt.Errorf("increase precision, max fake device number should less than %d", maxFakeTeeDevicesNum)
	}

	var devs = make([]*pluginapi.Device, deviceNum)
	for i, _ := range devs {
		devs[i] = &pluginapi.Device{
			ID:     fmt.Sprint(i),
			Health: pluginapi.Healthy,
		}
	}

	return devs, nil
}
