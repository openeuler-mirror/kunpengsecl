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
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// golbal definition

	// RasVersion means ras version
	RasVersion = "1.1.2"

	// path
	defaultMode     = 0755
	defaultTestMode = false
	strLocalConf    = "."
	strHomeConf     = "$HOME/.config/attestation/ras"
	strSysConf      = "/etc/attestation/ras"
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
	confHttpsPrivKeyFile = "rasconfig.httpsprivkeyfile"
	confHttpsKeyCertFile = "rasconfig.httpskeycertfile"
	confRootPrivKeyFile  = "rasconfig.rootprivkeyfile"
	confRootKeyCertFile  = "rasconfig.rootkeycertfile"
	confRimRootCertFile  = "rasconfig.rimrootcertfile"
	confPcaPrivKeyFile   = "rasconfig.pcaprivkeyfile"
	confPcaKeyCertFile   = "rasconfig.pcakeycertfile"
	confServerPort       = "rasconfig.serverport"
	confhttpsSwitch      = "rasconfig.httpsswitch"
	confRestPort         = "rasconfig.restport"
	confHttpsPort        = "rasconfig.httpsport"
	confAuthKeyFile      = "rasconfig.authkeyfile"
	confSerialNumber     = "rasconfig.serialnumber"
	confOnlineDuration   = "rasconfig.onlineduration"
	confHbDuration       = "racconfig.hbduration"
	confTrustDuration    = "racconfig.trustduration"
	confDigestAlgorithm  = "racconfig.digestalgorithm"
	confMgrStrategy      = "rasconfig.mgrstrategy"
	confTaVerifyType     = "rasconfig.taverifytype"
	confChangeTime       = "rasconfig.changetime"
	confExtRules         = "rasconfig.basevalue-extract-rules"
	// RAS config default value
	nullString      = ""
	rasLogFile      = "./logs/ras-log.txt"
	keyExt          = ".key"
	crtExt          = ".crt"
	rootKey         = "./pca-root"
	eKey            = "./pca-ek"
	httpsKey        = "./https"
	authKey         = "./ecdsakey"
	hbDuration      = 20   // seconds
	trustDuration   = 1200 // seconds
	digestAlgorithm = "sha1"
	strChina        = "China"
	strCompany      = "Company"
	strRootCA       = "Root CA"
	strPrivacyCA    = "Privacy CA"
	// ras test mode switcher
	lflagTest = "test"
	sflagTest = "t"
	helpTest  = "run in test mode[true] or not[false/default]"
	// server listen port
	lflagServerPort = "port"
	sflagServerPort = "p"
	helpServerPort  = "the server listens at [IP]:PORT"
	// HTTPS switch
	lflagHttpsSwitch = "https"
	sflagHttpsSwitch = "H"
	helpHttpsSwitch  = "the HTTPS switch"
	// rest api listen port
	lflagRestPort = "rest"
	sflagRestPort = "r"
	helpRestPort  = "the rest interface listens at [IP]:PORT"
	// rest api https listen port
	lflagHttpsPort = "hport"
	sflagHttpsPort = "h"
	helpHttpsPort  = "the https rest interface listens at [IP]:PORT"
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

	// AutoStrategy means mgr strategy is auto
	AutoStrategy = "auto"
	// ManualStrategy means mgr strategy is manual
	ManualStrategy = "manual"
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
		httpsPrivKeyFile string
		httpsKeyCertFile string
		httpsPrivKey     crypto.PrivateKey
		httpsKeyCert     *x509.Certificate
		rootPrivKeyFile  string
		rootKeyCertFile  string
		rootPrivKey      crypto.PrivateKey
		rootKeyCert      *x509.Certificate
		pcaPrivKeyFile   string
		pcaKeyCertFile   string
		pcaPrivKey       crypto.PrivateKey
		pcaKeyCert       *x509.Certificate
		rimRootCertFile  string
		rimRootCert      *x509.Certificate
		servPort         string
		httpsSwitch      string
		restPort         string
		httpsPort        string
		authKeyFile      string
		changeTime       time.Time
		mgrStrategy      string
		isallupdate      bool
		extractRules     typdefs.ExtractRules
		onlineDuration   time.Duration
		taVerifyType     int
		// rac configuration
		hbDuration      time.Duration // heartbeat duration
		trustDuration   time.Duration // trust state duration
		digestAlgorithm string

		testMode bool // ras test mode, nonce comparation is bypassed
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
	httpsSwitch *string = nil
	restPort    *string = nil
	httpsPort   *string = nil
	// VersionFlag means version flag
	VersionFlag *bool = nil
	verboseFlag *bool = nil
	// TokenFlag means token flag
	TokenFlag *bool = nil
	testMode  *bool = nil
)

// InitFlags inits the ras server command flags.
func InitFlags() {
	servPort = pflag.StringP(lflagServerPort, sflagServerPort, nullString, helpServerPort)
	testMode = pflag.BoolP(lflagTest, sflagTest, defaultTestMode, helpTest)
	httpsSwitch = pflag.StringP(lflagHttpsSwitch, sflagHttpsSwitch, nullString, helpHttpsSwitch)
	restPort = pflag.StringP(lflagRestPort, sflagRestPort, nullString, helpRestPort)
	httpsPort = pflag.StringP(lflagHttpsPort, sflagHttpsPort, nullString, helpHttpsPort)
	TokenFlag = pflag.BoolP(lflagToken, sflagToken, false, helpToken)
	VersionFlag = pflag.BoolP(lflagVersion, sflagVersion, false, helpVersion)
	verboseFlag = pflag.BoolP(lflagVerbose, sflagVerbose, true, helpVerbose)
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
	if httpsSwitch != nil && *httpsSwitch != nullString {
		SetHttpsSwitch(*httpsSwitch)
	}
	if restPort != nil && *restPort != nullString {
		SetRestPort(*restPort)
	}
	if httpsPort != nil && *httpsPort != nullString {
		SetHttpsPort(*httpsPort)
	}

	if testMode != nil && *testMode {
		SetTestMode(*testMode)
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
	rasCfg.httpsSwitch = viper.GetString(confhttpsSwitch)
	rasCfg.restPort = viper.GetString(confRestPort)
	rasCfg.httpsPort = viper.GetString(confHttpsPort)
	rasCfg.authKeyFile = viper.GetString(confAuthKeyFile)
	rasCfg.hbDuration = viper.GetDuration(confHbDuration)
	rasCfg.onlineDuration = viper.GetDuration(confOnlineDuration)
	rasCfg.trustDuration = viper.GetDuration(confTrustDuration)
	rasCfg.digestAlgorithm = viper.GetString(confDigestAlgorithm)
	rasCfg.mgrStrategy = viper.GetString(confMgrStrategy)
	rasCfg.taVerifyType = viper.GetInt(confTaVerifyType)
	var ers typdefs.ExtractRules
	if viper.UnmarshalKey(confExtRules, &ers) == nil {
		rasCfg.extractRules = ers
	} else {
		rasCfg.extractRules = typdefs.ExtractRules{}
	}
	cryptotools.SetSerialNumber(viper.GetInt64(confSerialNumber))
}

func createCertTemplate(t time.Time, c_type string) *x509.Certificate {
	switch c_type {
	case "root":
		rootTemplate := &x509.Certificate{
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
		return rootTemplate
	case "ek":
		ekTemplate := &x509.Certificate{
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
		return ekTemplate
	}
	return nil
}

// if no loading root ca key/cert, create and self-signing one
func createRootCertKey() {
	if rasCfg.rootPrivKey == nil {
		// modify rootTemplate fields
		t := time.Now()
		rootTemplate := createCertTemplate(t, "root")
		priv, err := rsa.GenerateKey(rand.Reader, cryptotools.RsaKeySize)
		if err != nil {
			return
		}
		// self signing
		certDer, err := x509.CreateCertificate(rand.Reader, rootTemplate,
			rootTemplate, &priv.PublicKey, priv)
		if err != nil {
			return
		}
		rasCfg.rootKeyCert, err = x509.ParseCertificate(certDer)
		if err == nil {
			rasCfg.rootPrivKey = priv
			// rasCfg.rootPrivKeyFile = rootKey + keyExt
			// rasCfg.rootKeyCertFile = rootKey + crtExt
			err = cryptotools.EncodePrivateKeyToFile(priv, rasCfg.rootPrivKeyFile)
			if err != nil {
				rasCfg.rootPrivKeyFile = rootKey + keyExt
				cryptotools.EncodePrivateKeyToFile(priv, rasCfg.rootPrivKeyFile)
			}
			err = cryptotools.EncodeKeyCertToFile(certDer, rasCfg.rootKeyCertFile)
			if err != nil {
				rasCfg.rootKeyCertFile = rootKey + crtExt
				cryptotools.EncodeKeyCertToFile(certDer, rasCfg.rootKeyCertFile)
			}
		}
	}
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
			// rasCfg.rootPrivKeyFile = nullString
		}
	} else {
		rasCfg.rootPrivKey = nil
	}
	rasCfg.rootKeyCertFile = viper.GetString(confRootKeyCertFile)
	if rasCfg.rootKeyCertFile != nullString {
		rasCfg.rootKeyCert, _, err = cryptotools.DecodeKeyCertFromFile(rasCfg.rootKeyCertFile)
		if err != nil {
			rasCfg.rootKeyCert = nil
			// rasCfg.rootKeyCertFile = nullString
			rasCfg.rootPrivKey = nil
			// rasCfg.rootPrivKeyFile = nullString
		}
	} else {
		rasCfg.rootKeyCert = nil
		rasCfg.rootPrivKey = nil
		// rasCfg.rootPrivKeyFile = nullString
	}
	createRootCertKey()
}

// getRimRootCert loads rim root certificate from file
func getRimRootCert() {
	var err error
	if rasCfg == nil {
		return
	}
	rasCfg.rimRootCertFile = viper.GetString(confRimRootCertFile)
	if rasCfg.rimRootCertFile != nullString {
		rasCfg.rimRootCert, _, err = cryptotools.DecodeKeyCertFromFile(rasCfg.rimRootCertFile)
		if err != nil {
			rasCfg.rimRootCert = nil
			rasCfg.rootPrivKey = nil
		}
	} else {
		rasCfg.rimRootCert = nil
	}
}

// if no loading pca key/cert, create and root-signing one
func createPcaCertKey() {
	if rasCfg.pcaPrivKey == nil {
		// modify rootTemplate fields
		t := time.Now()
		rootTemplate := createCertTemplate(t, "root")
		pcaTemplate := createCertTemplate(t, "ek")
		priv, err := rsa.GenerateKey(rand.Reader, cryptotools.RsaKeySize)
		if err != nil {
			return
		}
		// sign by root ca
		certDer, err := x509.CreateCertificate(rand.Reader, pcaTemplate,
			rootTemplate, &priv.PublicKey, rasCfg.rootPrivKey)
		if err != nil {
			return
		}
		rasCfg.pcaKeyCert, err = x509.ParseCertificate(certDer)
		if err == nil {
			rasCfg.pcaPrivKey = priv
			// rasCfg.pcaPrivKeyFile = eKey + keyExt
			// rasCfg.pcaKeyCertFile = eKey + crtExt
			err = cryptotools.EncodePrivateKeyToFile(priv, rasCfg.pcaPrivKeyFile)
			if err != nil {
				rasCfg.pcaPrivKeyFile = eKey + keyExt
				cryptotools.EncodePrivateKeyToFile(priv, rasCfg.pcaPrivKeyFile)
			}
			err = cryptotools.EncodeKeyCertToFile(certDer, rasCfg.pcaKeyCertFile)
			if err != nil {
				rasCfg.pcaKeyCertFile = eKey + crtExt
				cryptotools.EncodeKeyCertToFile(certDer, rasCfg.pcaKeyCertFile)
			}
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
			// rasCfg.pcaPrivKeyFile = nullString
		}
	} else {
		rasCfg.pcaPrivKey = nil
	}
	rasCfg.pcaKeyCertFile = viper.GetString(confPcaKeyCertFile)
	if rasCfg.pcaKeyCertFile != nullString {
		rasCfg.pcaKeyCert, _, err = cryptotools.DecodeKeyCertFromFile(rasCfg.pcaKeyCertFile)
		if err != nil {
			rasCfg.pcaKeyCert = nil
			// rasCfg.pcaKeyCertFile = nullString
			rasCfg.pcaPrivKey = nil
			// rasCfg.pcaPrivKeyFile = nullString
		}
	} else {
		rasCfg.pcaKeyCert = nil
		rasCfg.pcaPrivKey = nil
		// rasCfg.pcaPrivKeyFile = nullString
	}
	createPcaCertKey()
}

// if no loading https key/cert, create and root-signing one
func createHttpsCertKey() {
	if rasCfg.httpsPrivKey == nil {
		// modify rootTemplate fields
		t := time.Now()
		rootTemplate := createCertTemplate(t, "root")
		httpsTemplate := createCertTemplate(t, "ek")
		priv, err := rsa.GenerateKey(rand.Reader, cryptotools.RsaKeySize)
		if err != nil {
			return
		}
		// sign by root ca
		certDer, err := x509.CreateCertificate(rand.Reader, httpsTemplate,
			rootTemplate, &priv.PublicKey, rasCfg.rootPrivKey)
		if err != nil {
			return
		}
		rasCfg.httpsKeyCert, err = x509.ParseCertificate(certDer)
		if err == nil {
			rasCfg.httpsPrivKey = priv
			// rasCfg.httpsPrivKeyFile = httpsKey + keyExt
			// rasCfg.httpsKeyCertFile = httpsKey + crtExt
			err = cryptotools.EncodePrivateKeyToFile(priv, rasCfg.httpsPrivKeyFile)
			if err != nil {
				rasCfg.httpsPrivKeyFile = httpsKey + keyExt
				cryptotools.EncodePrivateKeyToFile(priv, rasCfg.httpsPrivKeyFile)
			}
			err = cryptotools.EncodeKeyCertToFile(certDer, rasCfg.httpsKeyCertFile)
			if err != nil {
				rasCfg.httpsKeyCertFile = httpsKey + crtExt
				cryptotools.EncodeKeyCertToFile(certDer, rasCfg.httpsKeyCertFile)
			}
		}
	}
}

// getHttpsKeyCert loads privacy https private key and certificate from files.
func getHttpsKeyCert() {
	var err error
	if rasCfg == nil {
		return
	}
	rasCfg.httpsPrivKeyFile = viper.GetString(confHttpsPrivKeyFile)
	if rasCfg.httpsPrivKeyFile != nullString {
		rasCfg.httpsPrivKey, _, err = cryptotools.DecodePrivateKeyFromFile(rasCfg.httpsPrivKeyFile)
		if err != nil {
			rasCfg.httpsPrivKey = nil
			// rasCfg.httpsPrivKeyFile = nullString
		}
	} else {
		rasCfg.httpsPrivKey = nil
	}
	rasCfg.httpsKeyCertFile = viper.GetString(confHttpsKeyCertFile)
	if rasCfg.httpsKeyCertFile != nullString {
		rasCfg.httpsKeyCert, _, err = cryptotools.DecodeKeyCertFromFile(rasCfg.httpsKeyCertFile)
		if err != nil {
			rasCfg.httpsKeyCert = nil
			// rasCfg.httpsKeyCertFile = nullString
			rasCfg.httpsPrivKey = nil
			// rasCfg.httpsPrivKeyFile = nullString
		}
	} else {
		rasCfg.httpsKeyCert = nil
		rasCfg.httpsPrivKey = nil
		// rasCfg.httpsPrivKeyFile = nullString
	}
	createHttpsCertKey()
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
		// default ras configure
		isallupdate: false,
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
	getRimRootCert()
	getPcaKeyCert()
	getHttpsKeyCert()
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
	viper.Set(confRimRootCertFile, rasCfg.rimRootCertFile)
	viper.Set(confPcaPrivKeyFile, rasCfg.pcaPrivKeyFile)
	viper.Set(confPcaKeyCertFile, rasCfg.pcaKeyCertFile)
	viper.Set(confHttpsPrivKeyFile, rasCfg.httpsPrivKeyFile)
	viper.Set(confHttpsKeyCertFile, rasCfg.httpsKeyCertFile)
	viper.Set(confServerPort, rasCfg.servPort)
	viper.Set(confhttpsSwitch, rasCfg.httpsSwitch)
	viper.Set(confRestPort, rasCfg.restPort)
	viper.Set(confHttpsPort, rasCfg.httpsPort)
	viper.Set(confAuthKeyFile, rasCfg.authKeyFile)
	viper.Set(confSerialNumber, cryptotools.GetSerialNumber())
	viper.Set(confHbDuration, rasCfg.hbDuration)
	viper.Set(confOnlineDuration, rasCfg.onlineDuration)
	viper.Set(confTrustDuration, rasCfg.trustDuration)
	viper.Set(confDigestAlgorithm, rasCfg.digestAlgorithm)
	viper.Set(confMgrStrategy, rasCfg.mgrStrategy)
	viper.Set(confTaVerifyType, rasCfg.taVerifyType)
	err := viper.WriteConfig()
	if err != nil {
		_ = viper.SafeWriteConfig()
	}
}

// GetTestMode returns the test mode configuration.
func GetTestMode() bool {
	if rasCfg == nil {
		return false
	}
	return rasCfg.testMode
}

// SetTestMode sets the test mode configuration.
func SetTestMode(m bool) {
	if rasCfg == nil {
		return
	}
	rasCfg.testMode = m
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

// GetExtractRules returns the ras extract rules configuration.
func GetExtractRules() typdefs.ExtractRules {
	return rasCfg.extractRules
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

// SetMgrStrategy sets the ras mgrStrategy configuration.
func SetMgrStrategy(s string) {
	if rasCfg == nil {
		return
	}
	rasCfg.mgrStrategy = s
}

// GetMgrStrategy returns the ras mgrStrategy configuration.
func GetMgrStrategy() string {
	if rasCfg == nil {
		return ""
	}
	return rasCfg.mgrStrategy
}

// SetIsAllUpdate sets the ras isallupdate configuration.
func SetIsAllUpdate(b bool) {
	if rasCfg == nil {
		return
	}
	rasCfg.isallupdate = b
}

// GetIsAllUpdate returns the ras isallupdate configuration.
func GetIsAllUpdate() *bool {
	if rasCfg == nil {
		return nil
	}
	return &rasCfg.isallupdate
}

// GetHttpsSwitch returns the ras restful api interface protocol(http or https) configuration.
func GetHttpsSwitch() bool {
	if rasCfg == nil {
		return true
	}
	httpsswitch, err := strconv.ParseBool(rasCfg.httpsSwitch)
	if err != nil {
		logger.L.Debug("get-httpsswitch output error")
		return true
	}
	return httpsswitch
}

// SetHttpsSwitch sets the ras restful api interface protocol(http or https) configuration.
func SetHttpsSwitch(p string) {
	if rasCfg == nil {
		return
	}
	rs, err := strconv.ParseBool(p)
	if err != nil {
		logger.L.Debug("set-httpsswitch input error")
		return
	}
	if rs {
		rasCfg.httpsSwitch = "true"
	} else {
		rasCfg.httpsSwitch = "false"
	}
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

// GetHttpsPort returns the ras restful api interface ip:port configuration.
func GetHttpsPort() string {
	if rasCfg == nil {
		return ""
	}
	return rasCfg.httpsPort
}

// SetHttpsPort sets the ras restful api interface ip:port configuration.
func SetHttpsPort(s string) {
	if rasCfg == nil {
		return
	}
	rasCfg.httpsPort = s
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

// GetRimRootCert returns the root key certificate configuration for RIM signature check.
func GetRimRootCert() *x509.Certificate {
	if rasCfg == nil {
		return nil
	}
	return rasCfg.rimRootCert
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

// GetHttpsPrivateKey returns the https private key configuration.
func GetHttpsPrivateKey() crypto.PrivateKey {
	if rasCfg == nil {
		return nil
	}
	return rasCfg.httpsPrivKey
}

// GetHttpsKeyCert returns the https key certificate configuration.
func GetHttpsKeyCert() *x509.Certificate {
	if rasCfg == nil {
		return nil
	}
	return rasCfg.httpsKeyCert
}

// GetHttpsPrivateKeyFile returns the HttpsPrivateKeyFile configuration.
func GetHttpsPrivateKeyFile() string {
	if rasCfg == nil {
		return ""
	}
	return rasCfg.httpsPrivKeyFile
}

// GetHttpsKeyCertFile returns the HttpsKeyCertFile configuration.
func GetHttpsKeyCertFile() string {
	if rasCfg == nil {
		return ""
	}
	return rasCfg.httpsKeyCertFile
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

// SetHBDuration sets heart beat duration configuration.
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

// SetOnlineDuration sets client online expire duration configuration.
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

// SetTrustDuration sets trust report expire duration configuration.
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

// SetDigestAlgorithm sets digest algorithm configuration.
func SetDigestAlgorithm(s string) {
	if rasCfg == nil {
		return
	}
	rasCfg.digestAlgorithm = s
}

// SetLoggerMode sets ras log file configuration.
func SetLoggerMode(testMode bool) {
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
	*verboseFlag = testMode
	if testMode {
		logger.L = logger.NewDebugLogger(logF)
	} else {
		logger.L = logger.NewInfoLogger(logF)
	}
	rasCfg.logFile = logF
}

// GetLoggerMode returns ras log file configuration.
func GetLoggerMode() *bool {
	if rasCfg == nil {
		return nil
	}
	return verboseFlag
}

// SetExtractRules sets the ras extract rules configuration.
func SetExtractRules(val string) {
	byteER := []byte(val)
	var extractRules typdefs.ExtractRules
	err := json.Unmarshal(byteER, &extractRules)
	if err != nil {
		log.Print("Unmarshal byte to struct failed.")
		return
	}
	rasCfg.extractRules = extractRules
}

// GetTaInputs return ta inputs.
func GetTaInputs() map[string]typdefs.TaReportInput {
	taInputs := map[string]typdefs.TaReportInput{}
	return taInputs
}

// vtype shuold be 1/2/3
// SetTaVerifyType sets ta verify type configuration.
func SetTaVerifyType(vtype int) {
	rasCfg.taVerifyType = vtype
}

// GetTaVerifyType returns ta verify type configuration.
func GetTaVerifyType() int {
	return rasCfg.taVerifyType
}
