/*
Copyright (c) Huawei Technologies Co., Ltd. 2021.
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun
Create: 2021-12-08
Description:
  this package restores common structs and functions used in the project,
  don't need to invoke others.
*/

package entity

import (
	"net"
	"time"
)

// Report is a trust report, normally it is send by RAC
type Report struct {
	PcrInfo       PcrInfo
	Manifest      []Manifest
	ClientID      int64
	ClientInfo    ClientInfo
	Verified      bool
	ReportId      int64
	ClientInfoVer int
	ReportTime    time.Time
}

type RegisterClient struct {
	ClientID      int64
	ClientInfoVer int
	RegisterTime  time.Time
	AkCertificate string
	IsOnline      bool
	IsDeleted     bool
	BaseValueVer  int
}

/*
	TransformReport is used when receiving data from rac and after validate process,
	it will be converted to Report
*/
type TransformReport struct {
	PcrInfo    PcrInfo
	Manifest   []Manifest
	ClientID   int64
	ClientInfo string
	Verified   bool
}

/*
	PcrInfo contains information of every pcr.
	Quote is signed by RAC TPM and will be decrypted for validating identity
*/
type PcrInfo struct {
	Values map[int]string
	Quote  PcrQuote
}

type PcrQuote struct {
	Quoted    []byte
	Signature []byte
}

/*
	Manifest is a list of measurement
*/
type Manifest struct {
	Type  string // bios/ima
	Items []ManifestItem
}

type ManifestItem struct {
	Name   string
	Value  string
	Detail string // json string
}

type ClientInfo struct {
	Info map[string]string
}

type MeasurementInfo struct {
	ClientID int64
	PcrInfo  PcrInfo
	Manifest []Measurement
}

type Measurement struct {
	Type  string // bios/ima
	Name  string
	Value string
}

type ExtractRules struct {
	PcrRule       PcrRule        `mapstructure:"pcrinfo"`
	ManifestRules []ManifestRule `mapstructure:"manifest"`
}
type PcrRule struct {
	PcrSelection []int `mapstructure:"pcrselection"`
}
type ManifestRule struct {
	MType string   `mapstructure:"type"`
	Name  []string `mapstructure:"name"`
}
type AutoUpdateConfig struct {
	IsAllUpdate   bool
	UpdateClients []int64
}

// for generating detail in ManifestItem
type BIOSManifestItem struct {
	Pcr     uint32
	BType   uint32
	Digest  DigestValues
	DataLen uint32
	Data    string
}
type DigestValues struct {
	Count uint32
	Item  []DigestItem
}
type DigestItem struct {
	AlgID string
	Item  string
}
type IMAManifestItem struct {
	Pcr          string
	TemplateHash string
	TemplateName string
	FiledataHash string
	FilenameHint string
}

type Container struct {
	UUID         string
	ClientId     int64
	BaseValueVer int
	Online       bool
	Deleted      bool
}

type ContainerBaseValue struct {
	ContainerUUID string
	Value         map[string]string
}

type PcieDevice struct {
	ID           int64
	ClientId     int64
	BaseValueVer int
	Online       bool
	Deleted      bool
}

type PcieBaseValue struct {
	DeviceID int64
	Value    map[string]string
}

// GetIP returns the host ipv4 address
func GetIP() (string, bool) {
	netIfs, err := net.Interfaces()
	if err != nil {
		return "", false
	}
	for i := 0; i < len(netIfs); i++ {
		if (netIfs[i].Flags & net.FlagUp) != 0 {
			addrs, _ := netIfs[i].Addrs()
			for _, addr := range addrs {
				ip, ok := addr.(*net.IPNet)
				if ok && !ip.IP.IsLoopback() && ip.IP.To4() != nil {
					return ip.IP.String(), true
				}
			}
		}
	}
	return "", false
}
