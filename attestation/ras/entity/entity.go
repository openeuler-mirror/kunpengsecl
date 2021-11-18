package entity

import (
	"time"
)

/*
	this package restores struct used in the project
*/

/*
	Report is a trust report, normally it is send by RAC
*/
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
	AlgName string
	Values  map[int]string
	Quote   PcrQuote
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
	PcrRule       PcrRule
	ManifestRules []ManifestRule
}
type PcrRule struct {
	PcrSelection []int
}
type ManifestRule struct {
	MType string
	Name  []string
}

// for generating detail in ManifestItem
type BIOSManifestItem struct {
	Pcr  string
	Hash string
	Name string
}
type IMAManifestItem struct {
	Pcr          string
	TemplateHash string
	TemplateName string
	FiledataHash string
	FilenameHint string
}
