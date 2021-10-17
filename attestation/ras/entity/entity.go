package entity

/*
	this package restores struct used in the project
*/

/*
	Report is a trust report, normally it is send by RAC
*/
type Report struct {
	PcrInfo    PcrInfo
	Manifest   []Manifest
	ClientID   int64
	ClientInfo ClientInfo
	Verified   bool
}

/*
	PcrInfo contains information of every pcr.
	Quote is signed by RAC TPM and will be decrypted for validating identity
*/
type PcrInfo struct {
	AlgName string
	Values  []PcrValue
	Quote   PcrQuote
}

type PcrValue struct {
	Id    int
	Value string
}

type PcrQuote []byte

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
