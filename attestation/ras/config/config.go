/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun
Create: 2022-01-17
Description: config package for ras.
*/

// config package for ras.
package config

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// golbal definition
	RasVersion = "2.0.0"

	// path
	defaultMode  = 0755
	strLocalConf = "."
	strHomeConf  = "$HOME/.config/attestation/ras"
	strSysConf   = "/etc/attestation/ras"
	// config file name
	confName = "config"
	confExt  = "yaml"
	// database
	dbHost        = "database.host"
	dbName        = "database.name"
	dbPort        = "database.port"
	dbUser        = "database.user"
	dbPassword    = "database.password"
	dbHostDefault = "localhost"
	dbNameDefault = "kunpengsecl"
	dbUserDefault = "postgres"
	dbPortDefault = 5432
	// logger
	logFile = "log.file"
	// RAS config key
	confRootPrivKeyFile = "rasconfig.rootprivkeyfile"
	confRootKeyCertFile = "rasconfig.rootkeycertfile"
	confPcaPrivKeyFile  = "rasconfig.pcaprivkeyfile"
	confPcaKeyCertFile  = "rasconfig.pcakeycertfile"
	confServerPort      = "rasconfig.serverport"
	confRestPort        = "rasconfig.restport"
	confAuthKeyFile     = "rasconfig.authkeyfile"
	confSerialNumber    = "rasconfig.serialnumber"
	confOnlineDuration  = "rasconfig.onlineduration"
	confHbDuration      = "racconfig.hbduration"
	confTrustDuration   = "racconfig.trustduration"
	confDigestAlgorithm = "racconfig.digestalgorithm"
	// RAS config default value
	nullString      = ""
	rasLogFile      = "./logs/ras-log.txt"
	keyExt          = ".key"
	crtExt          = ".crt"
	rootKey         = "./pca-root"
	eKey            = "./pca-ek"
	authKey         = "./ecdsakey"
	hbDuration      = 20   // seconds
	trustDuration   = 1200 // seconds
	digestAlgorithm = "sha1"
	strChina        = "China"
	strCompany      = "Company"
	strRootCA       = "Root CA"
	strPrivacyCA    = "Privacy CA"
	// server listen port
	lflagServerPort = "port"
	sflagServerPort = "p"
	helpServerPort  = "the server listens at [IP]:PORT"
	// rest api listen port
	lflagRestPort = "rest"
	sflagRestPort = "r"
	helpRestPort  = "the rest interface listens at [IP]:PORT"
	// token output
	lflagToken = "token"
	sflagToken = "T"
	helpToken  = "generate test token for rest api"
	// version output
	lflagVersion = "version"
	sflagVersion = "V"
	helpVersion  = "show version number and quit"
	// verbose output
	lflagVerbose = "verbose"
	sflagVerbose = "v"
	helpVerbose  = "show running debug information"
	//mgr strategy
	mgrStrategy        = "rasconfig.mgrstrategy"
	AutoStrategy       = "auto"
	AutoUpdateStrategy = "auto-update"
	changeTime         = "rasconfig.changetime"
	extRules           = "rasconfig.basevalue-extract-rules"
	autoUpdateConfig   = "rasconfig.auto-update-config"
)

type (
	rasConfig struct {
		// logger file
		logFile string
		ip      string

		// database configuration
		dbHost     string
		dbName     string
		dbUser     string
		dbPassword string
		dbPort     int

		// ras configuration
		rootPrivKeyFile  string
		rootKeyCertFile  string
		rootPrivKey      crypto.PrivateKey
		rootKeyCert      *x509.Certificate
		pcaPrivKeyFile   string
		pcaKeyCertFile   string
		pcaPrivKey       crypto.PrivateKey
		pcaKeyCert       *x509.Certificate
		servPort         string
		restPort         string
		authKeyFile      string
		changeTime       time.Time
		mgrStrategy      string
		extractRules     typdefs.ExtractRules
		autoUpdateConfig typdefs.AutoUpdateConfig
		onlineDuration   time.Duration
		// rac configuration
		hbDuration      time.Duration // heartbeat duration
		trustDuration   time.Duration // trust state duration
		digestAlgorithm string
	}
)

var (
	defaultPaths = []string{
		strLocalConf,
		strHomeConf,
		strSysConf,
	}
	rasCfg      *rasConfig
	servPort    *string = nil
	restPort    *string = nil
	VersionFlag *bool   = nil
	verboseFlag *bool   = nil
	TokenFlag   *bool   = nil
)

// InitFlags inits the ras server command flags.
func InitFlags() {
	servPort = pflag.StringP(lflagServerPort, sflagServerPort, nullString, helpServerPort)
	restPort = pflag.StringP(lflagRestPort, sflagRestPort, nullString, helpRestPort)
	TokenFlag = pflag.BoolP(lflagToken, sflagToken, false, helpToken)
	VersionFlag = pflag.BoolP(lflagVersion, sflagVersion, false, helpVersion)
	verboseFlag = pflag.BoolP(lflagVerbose, sflagVerbose, false, helpVerbose)
	pflag.Parse()
}

// HandleFlags handles the command flags.
func HandleFlags() {
	// init logger
	logF := GetLogFile()
	logD := filepath.Dir(logF)
	if logF == nullString {
		logF = rasLogFile
		logD = filepath.Dir(logF)
	}
	err := os.MkdirAll(logD, defaultMode)
	if err != nil {
		fmt.Printf("mkdir '%s' error: %v\n", logD, err)
	}
	if verboseFlag != nil && *verboseFlag {
		logger.L = logger.NewDebugLogger(logF)
	} else {
		logger.L = logger.NewInfoLogger(logF)
	}
	rasCfg.logFile = logF
	// set command line input
	if servPort != nil && *servPort != nullString {
		SetServerPort(*servPort)
	}
	if restPort != nil && *restPort != nullString {
		SetRestPort(*restPort)
	}
}

// getConfigs gets all config from config.yaml file.
func getConfigs() {
	if rasCfg == nil {
		return
	}
	rasCfg.logFile = viper.GetString(logFile)
	rasCfg.ip = typdefs.GetIP()
	rasCfg.dbHost = viper.GetString(dbHost)
	rasCfg.dbName = viper.GetString(dbName)
	rasCfg.dbPort = viper.GetInt(dbPort)
	rasCfg.dbUser = viper.GetString(dbUser)
	rasCfg.dbPassword = viper.GetString(dbPassword)
	rasCfg.servPort = viper.GetString(confServerPort)
	rasCfg.restPort = viper.GetString(confRestPort)
	rasCfg.authKeyFile = viper.GetString(confAuthKeyFile)
	rasCfg.hbDuration = viper.GetDuration(confHbDuration)
	rasCfg.onlineDuration = viper.GetDuration(confOnlineDuration)
	rasCfg.trustDuration = viper.GetDuration(confTrustDuration)
	rasCfg.digestAlgorithm = viper.GetString(confDigestAlgorithm)
	rasCfg.mgrStrategy = viper.GetString(mgrStrategy)
	var ers typdefs.ExtractRules
	if viper.UnmarshalKey(extRules, &ers) == nil {
		rasCfg.extractRules = ers
	} else {
		rasCfg.extractRules = typdefs.ExtractRules{}
	}
	var auc typdefs.AutoUpdateConfig
	if viper.UnmarshalKey(autoUpdateConfig, &auc) == nil {
		rasCfg.autoUpdateConfig = auc
	} else {
		rasCfg.autoUpdateConfig = typdefs.AutoUpdateConfig{}
	}
	cryptotools.SetSerialNumber(viper.GetInt64(confSerialNumber))
}

// getRootKeyCert loads root private key and certificate from files.
func getRootKeyCert() {
	var err error
	if rasCfg == nil {
		return
	}
	rasCfg.rootPrivKeyFile = viper.GetString(confRootPrivKeyFile)
	if rasCfg.rootPrivKeyFile != nullString {
		rasCfg.rootPrivKey, _, err = cryptotools.DecodePrivateKeyFromFile(rasCfg.rootPrivKeyFile)
		if err != nil {
			rasCfg.rootPrivKey = nil
			rasCfg.rootPrivKeyFile = nullString
		}
	} else {
		rasCfg.rootPrivKey = nil
	}
	rasCfg.rootKeyCertFile = viper.GetString(confRootKeyCertFile)
	if rasCfg.rootKeyCertFile != nullString {
		rasCfg.rootKeyCert, _, err = cryptotools.DecodeKeyCertFromFile(rasCfg.rootKeyCertFile)
		if err != nil {
			rasCfg.rootKeyCert = nil
			rasCfg.rootKeyCertFile = nullString
			rasCfg.rootPrivKey = nil
			rasCfg.rootPrivKeyFile = nullString
		}
	} else {
		rasCfg.rootKeyCert = nil
		rasCfg.rootPrivKey = nil
		rasCfg.rootPrivKeyFile = nullString
	}
	// if no loading root ca key/cert, create and self-signing one
	if rasCfg.rootPrivKey == nil {
		// modify rootTemplate fields
		t := time.Now()
		rootTemplate := x509.Certificate{
			SerialNumber: big.NewInt(cryptotools.GetSerialNumber()),
			Subject: pkix.Name{
				Country:      []string{strChina},
				Organization: []string{strCompany},
				CommonName:   strRootCA,
			},
			NotBefore:             t.Add(-10 * time.Second),
			NotAfter:              t.AddDate(10, 0, 0),
			KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            2,
			IPAddresses:           []net.IP{net.ParseIP(typdefs.GetIP())},
		}
		priv, _ := rsa.GenerateKey(rand.Reader, cryptotools.RsaKeySize)
		// self signing
		certDer, err := x509.CreateCertificate(rand.Reader, &rootTemplate,
			&rootTemplate, &priv.PublicKey, priv)
		if err != nil {
			return
		}
		rasCfg.rootKeyCert, err = x509.ParseCertificate(certDer)
		if err == nil {
			rasCfg.rootPrivKey = priv
			rasCfg.rootPrivKeyFile = rootKey + keyExt
			rasCfg.rootKeyCertFile = rootKey + crtExt
			cryptotools.EncodePrivateKeyToFile(priv, rasCfg.rootPrivKeyFile)
			cryptotools.EncodeKeyCertToFile(certDer, rasCfg.rootKeyCertFile)
		}
	}
}

// getPcaKeyCert loads privacy ca(pca) private key and certificate from files.
func getPcaKeyCert() {
	var err error
	if rasCfg == nil {
		return
	}
	rasCfg.pcaPrivKeyFile = viper.GetString(confPcaPrivKeyFile)
	if rasCfg.pcaPrivKeyFile != nullString {
		rasCfg.pcaPrivKey, _, err = cryptotools.DecodePrivateKeyFromFile(rasCfg.pcaPrivKeyFile)
		if err != nil {
			rasCfg.pcaPrivKey = nil
			rasCfg.pcaPrivKeyFile = nullString
		}
	} else {
		rasCfg.pcaPrivKey = nil
	}
	rasCfg.pcaKeyCertFile = viper.GetString(confPcaKeyCertFile)
	if rasCfg.pcaKeyCertFile != nullString {
		rasCfg.pcaKeyCert, _, err = cryptotools.DecodeKeyCertFromFile(rasCfg.pcaKeyCertFile)
		if err != nil {
			rasCfg.pcaKeyCert = nil
			rasCfg.pcaKeyCertFile = nullString
			rasCfg.pcaPrivKey = nil
			rasCfg.pcaPrivKeyFile = nullString
		}
	} else {
		rasCfg.pcaKeyCert = nil
		rasCfg.pcaPrivKey = nil
		rasCfg.pcaPrivKeyFile = nullString
	}
	if rasCfg.pcaPrivKey == nil {
		// modify rootTemplate fields
		t := time.Now()
		rootTemplate := x509.Certificate{
			SerialNumber: big.NewInt(cryptotools.GetSerialNumber()),
			Subject: pkix.Name{
				Country:      []string{strChina},
				Organization: []string{strCompany},
				CommonName:   strRootCA,
			},
			NotBefore:             t.Add(-10 * time.Second),
			NotAfter:              t.AddDate(10, 0, 0),
			KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            2,
			IPAddresses:           []net.IP{net.ParseIP(typdefs.GetIP())},
		}
		pcaTemplate := x509.Certificate{
			SerialNumber: big.NewInt(cryptotools.GetSerialNumber()),
			Subject: pkix.Name{
				Country:      []string{strChina},
				Organization: []string{strCompany},
				CommonName:   strPrivacyCA,
			},
			NotBefore:             t.Add(-10 * time.Second),
			NotAfter:              t.AddDate(1, 0, 0),
			KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLenZero:        false,
			MaxPathLen:            1,
			IPAddresses:           []net.IP{net.ParseIP(typdefs.GetIP())},
		}
		priv, _ := rsa.GenerateKey(rand.Reader, cryptotools.RsaKeySize)
		// sign by root ca
		certDer, err := x509.CreateCertificate(rand.Reader, &pcaTemplate,
			&rootTemplate, &priv.PublicKey, rasCfg.rootPrivKey)
		if err != nil {
			return
		}
		rasCfg.pcaKeyCert, err = x509.ParseCertificate(certDer)
		if err == nil {
			rasCfg.pcaPrivKey = priv
			rasCfg.pcaPrivKeyFile = eKey + keyExt
			rasCfg.pcaKeyCertFile = eKey + crtExt
			cryptotools.EncodePrivateKeyToFile(priv, rasCfg.pcaPrivKeyFile)
			cryptotools.EncodeKeyCertToFile(certDer, rasCfg.pcaKeyCertFile)
		}
	}
}

// LoadConfigs searches and loads config from config.yaml file.
func LoadConfigs() {
	if rasCfg != nil {
		return
	}

	// set default values
	rasCfg = &rasConfig{
		// default database
		dbHost:     dbHostDefault,
		dbName:     dbNameDefault,
		dbUser:     dbUserDefault,
		dbPassword: dbUserDefault,
		dbPort:     dbPortDefault,
		// default rac configure
		hbDuration:      hbDuration,
		trustDuration:   trustDuration,
		digestAlgorithm: digestAlgorithm,
	}
	// set config.yaml loading name and path
	viper.SetConfigName(confName)
	viper.SetConfigType(confExt)
	for _, s := range defaultPaths {
		viper.AddConfigPath(s)
	}
	err := viper.ReadInConfig()
	if err != nil {
		//fmt.Printf("read config file error: %v\n", err)
		return
	}
	getConfigs()
	getRootKeyCert()
	getPcaKeyCert()
}

// SaveConfigs saves all config variables to the config.yaml file.
func SaveConfigs() {
	if rasCfg == nil {
		return
	}
	viper.Set(logFile, rasCfg.logFile)
	viper.Set(dbHost, rasCfg.dbHost)
	viper.Set(dbName, rasCfg.dbName)
	viper.Set(dbPort, rasCfg.dbPort)
	viper.Set(dbUser, rasCfg.dbUser)
	viper.Set(dbPassword, rasCfg.dbPassword)
	viper.Set(confRootPrivKeyFile, rasCfg.rootPrivKeyFile)
	viper.Set(confRootKeyCertFile, rasCfg.rootKeyCertFile)
	viper.Set(confPcaPrivKeyFile, rasCfg.pcaPrivKeyFile)
	viper.Set(confPcaKeyCertFile, rasCfg.pcaKeyCertFile)
	viper.Set(confServerPort, rasCfg.servPort)
	viper.Set(confRestPort, rasCfg.restPort)
	viper.Set(confAuthKeyFile, rasCfg.authKeyFile)
	viper.Set(confSerialNumber, cryptotools.GetSerialNumber())
	viper.Set(confHbDuration, rasCfg.hbDuration)
	viper.Set(confOnlineDuration, rasCfg.onlineDuration)
	viper.Set(confTrustDuration, rasCfg.trustDuration)
	viper.Set(confDigestAlgorithm, rasCfg.digestAlgorithm)
	err := viper.WriteConfig()
	if err != nil {
		_ = viper.SafeWriteConfig()
	}
}

// GetLogFile returns the logger path configuration.
func GetLogFile() string {
	if rasCfg == nil {
		return rasLogFile
	}
	return rasCfg.logFile
}

// GetIP returns the ras server ip address.
func GetIP() string {
	if rasCfg == nil {
		return ""
	}
	return rasCfg.ip
}

// GetDBHost returns the database host configuration.
func GetDBHost() string {
	if rasCfg == nil {
		return ""
	}
	return rasCfg.dbHost
}

// SetDBHost sets the database host configuration.
func SetDBHost(host string) {
	if rasCfg == nil {
		return
	}
	rasCfg.dbHost = host
}

// GetDBName returns the database name configuration.
func GetDBName() string {
	if rasCfg == nil {
		return ""
	}
	return rasCfg.dbName
}

// SetDBName sets the database name configuration.
func SetDBName(dbName string) {
	if rasCfg == nil {
		return
	}
	rasCfg.dbName = dbName
}

// GetDBPort returns the database port configuration.
func GetDBPort() int {
	if rasCfg == nil {
		return -1
	}
	return rasCfg.dbPort
}

// SetDBPort sets the database port configuration.
func SetDBPort(port int) {
	if rasCfg == nil {
		return
	}
	rasCfg.dbPort = port
}

// GetDBUser returns the database user name configuration.
func GetDBUser() string {
	if rasCfg == nil {
		return ""
	}
	return rasCfg.dbUser
}

// SetDBUser sets the database user name configuration.
func SetDBUser(user string) {
	if rasCfg == nil {
		return
	}
	rasCfg.dbUser = user
}

// GetDBPassword returns the database user password configuration.
func GetDBPassword() string {
	if rasCfg == nil {
		return ""
	}
	return rasCfg.dbPassword
}

// SetDBPassword sets the database user password configuration.
func SetDBPassword(password string) {
	if rasCfg == nil {
		return
	}
	rasCfg.dbPassword = password
}

func GetExtractRules() typdefs.ExtractRules {
	return rasCfg.extractRules
}

func SetAutoUpdateConfig(auc typdefs.AutoUpdateConfig) {
	rasCfg.autoUpdateConfig = auc
}

func GetAutoUpdateConfig() typdefs.AutoUpdateConfig {
	return rasCfg.autoUpdateConfig
}

// GetServerPort returns the ras service ip:port configuration.
func GetServerPort() string {
	if rasCfg == nil {
		return ""
	}
	return rasCfg.servPort
}

// SetServerPort sets the ras service ip:port configuration.
func SetServerPort(s string) {
	if rasCfg == nil {
		return
	}
	rasCfg.servPort = s
}

// GetRestPort returns the ras restful api interface ip:port configuration.
func GetRestPort() string {
	if rasCfg == nil {
		return ""
	}
	return rasCfg.restPort
}

// SetRestPort sets the ras restful api interface ip:port configuration.
func SetRestPort(s string) {
	if rasCfg == nil {
		return
	}
	rasCfg.restPort = s
}

// GetRootPrivateKey returns the root private key configuration.
func GetRootPrivateKey() crypto.PrivateKey {
	if rasCfg == nil {
		return nil
	}
	return rasCfg.rootPrivKey
}

// GetRootKeyCert returns the root key certificate configuration.
func GetRootKeyCert() *x509.Certificate {
	if rasCfg == nil {
		return nil
	}
	return rasCfg.rootKeyCert
}

// GetPcaPrivateKey returns the pca private key configuration.
func GetPcaPrivateKey() crypto.PrivateKey {
	if rasCfg == nil {
		return nil
	}
	return rasCfg.pcaPrivKey
}

// GetPcaKeyCert returns the pca key certificate configuration.
func GetPcaKeyCert() *x509.Certificate {
	if rasCfg == nil {
		return nil
	}
	return rasCfg.pcaKeyCert
}

// GetAuthKeyFile returns the auth token key configuration.
func GetAuthKeyFile() string {
	if rasCfg == nil {
		return ""
	}
	return rasCfg.authKeyFile
}

// SetAuthKeyFile sets the auth token key configuration.
func SetAuthKeyFile(filename string) {
	if rasCfg == nil {
		return
	}
	rasCfg.authKeyFile = filename
}

// GetHBDuration returns heart beat duration configuration.
func GetHBDuration() time.Duration {
	if rasCfg == nil {
		return 0
	}
	return rasCfg.hbDuration
}

// SetHBDuration returns heart beat duration configuration.
func SetHBDuration(v time.Duration) {
	if rasCfg == nil {
		return
	}
	rasCfg.hbDuration = v
}

// GetOnlineDuration returns client online expire duration configuration.
func GetOnlineDuration() time.Duration {
	if rasCfg == nil {
		return 0
	}
	return rasCfg.onlineDuration
}

// SetOnlineDuration returns client online expire duration configuration.
func SetOnlineDuration(v time.Duration) {
	if rasCfg == nil {
		return
	}
	rasCfg.onlineDuration = v
}

// GetTrustDuration returns trust report expire duration configuration.
func GetTrustDuration() time.Duration {
	if rasCfg == nil {
		return 0
	}
	return rasCfg.trustDuration
}

// SetTrustDuration returns trust report expire duration configuration.
func SetTrustDuration(v time.Duration) {
	if rasCfg == nil {
		return
	}
	rasCfg.trustDuration = v
}

// GetDigestAlgorithm returns digest algorithm configuration.
func GetDigestAlgorithm() string {
	if rasCfg == nil {
		return ""
	}
	return rasCfg.digestAlgorithm
}
