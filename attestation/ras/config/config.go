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
Create: 2021-09-17
Description: Store RAS and RAC configurations.
*/

package config

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/pca"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// app
	appRas   = "ras"
	appRac   = "rac"
	appRahub = "rahub"
	// path
	strPathLocal     = "."
	strPathLocalConf = "./config"
	strPathHomeConf  = "$HOME/.config/attestation/"
	strPathSysConf   = "/etc/attestation/"
	strPathHomeRas   = strPathHomeConf + appRas
	strPathHomeRac   = strPathHomeConf + appRac
	strPathHomeRahub = strPathHomeConf + appRahub
	strPathSysRas    = strPathSysConf + appRas
	strPathSysRac    = strPathSysConf + appRac
	strPathSysRahub  = strPathSysConf + appRahub
	// normal
	ConfName   = "config"
	ConfExt    = "yaml"
	ConfServer = "server"
	ConfClient = "client"
	ConfHub    = "hub"
	// database
	DbHost     = "database.host"
	DbName     = "database.dbname"
	DbPort     = "database.port"
	DbUser     = "database.user"
	DbPassword = "database.password"
	// RAS
	NullString            = ""
	extKey                = ".key"
	extCert               = ".crt"
	RasRootKeyFileDefault = "./pca-root"
	RasPcaKeyFileDefault  = "./pca-ek"
	RasRootPrivKeyFile    = "rasconfig.rootprivkeyfile"
	RasRootKeyCertFile    = "rasconfig.rootkeycertfile"
	RasPcaPrivKeyFile     = "rasconfig.pcaprivkeyfile"
	RasPcaKeyCertFile     = "rasconfig.pcakeycertfile"
	RasPort               = "rasconfig.port" // server listen port
	RasPortLongFlag       = "port"
	RasPortShortFlag      = "p"
	RasPortHelp           = "this app service listen at [IP]:PORT"
	RasRestPort           = "rasconfig.rest" // rest listen port
	RasRestPortLongFlag   = "rest"
	RasRestPortShortFlag  = "r"
	RasRestHelp           = "this app rest interface listen at [IP]:PORT"
	VerboseLongFlag       = "verbose"
	VerboseShortFlag      = "v"
	VerboseHelp           = "show more detail running information"
	VersionLongFlag       = "version"
	VersionShortFlag      = "V"
	VersionHelp           = "show version number and quit"
	RasTokenLongFlag      = "token"
	RasTokenShortFlag     = "T"
	RasTokenHelp          = "generate test token and quit"
	RasMgrStrategy        = "rasconfig.mgrstrategy"
	RasAutoStrategy       = "auto"
	RasAutoUpdateStrategy = "auto-update"
	RasChangeTime         = "rasconfig.changetime"
	RasExtRules           = "rasconfig.basevalue-extract-rules"
	RasAutoUpdateConfig   = "rasconfig.auto-update-config"
	RasAuthKeyFile        = "rasconfig.authkeyfile"
	RasAuthKeyFileDefault = "./ecdsakey"
	// RAC
	RacIPriKeyFileDefault      = "./ikpri"
	RacIPubKeyFileDefault      = "./ikpub"
	RacIKeyCertFileDefault     = "./ic"
	RacEKeyCertFile            = "racconfig.ekcert"
	RacIPriKeyFile             = "racconfig.ikprikey"
	RacIPubKeyFile             = "racconfig.ikpubkey"
	RacIKeyCertFile            = "racconfig.ikcert"
	RacEKFileDefaultTest       = "./ectest"
	RacIPriKeyFileDefaultTest  = "./ikpritest"
	RacIPubKeyFileDefaultTest  = "./ikpubtest"
	RacIKeyCertFileDefaultTest = "./ictest"
	RacEKeyCertFileTest        = "racconfig.ekcerttest"
	RacIPriKeyFileTest         = "racconfig.ikprikeytest"
	RacIPubKeyFileTest         = "racconfig.ikpubkeytest"
	RacIKeyCertFileTest        = "racconfig.ikcerttest"
	RacServer                  = "racconfig.server" // client connect to server
	RacServerLongFlag          = "server"
	RacServerShortFlag         = "s"
	RacServerHelp              = "connect attestation server at IP:PORT"
	RacTestModeLongFlag        = "test"
	RacTestModeShortFlag       = "t"
	RacTestModeHelp            = "run in test mode[true] or not[false/default]"
	RacHbDuration              = "racconfig.hbduration"
	RacDefaultHbDuration       = 10 // seconds
	RacTrustDuration           = "racconfig.trustduration"
	RacDefaultTrustDuration    = 120 // seconds
	RacClientId                = "racconfig.clientid"
	RacNullClientId            = -1
	RacPassword                = "racconfig.password"
	RacDefaultPassword         = ""
	RacDigestAlgorithm         = "racconfig.digestalgorithm"
	RacDigestAlgorithmSHA256   = "sha256"
	// Hub
	HubServer          = "hubconfig.server"
	HubServerLongFlag  = "server"
	HubServerShortFlag = "s"
	HubPort            = "hubconfig.hubport"
	HubPortLongFlag    = "hubport"
	HubPortShortFlag   = "p"
	HubPortHelp        = "rahub listen at [IP]:PORT"
)

var (
	defaultRasConfigPath = []string{
		strPathLocal,
		strPathLocalConf,
		strPathHomeRas,
		strPathSysRas,
	}
	defaultRacConfigPath = []string{
		strPathLocal,
		strPathLocalConf,
		strPathHomeRac,
		strPathSysRac,
	}
	defaultRahubConfigPath = []string{
		strPathLocal,
		strPathLocalConf,
		strPathHomeRahub,
		strPathSysRahub,
	}
	confG       *config
	VerboseFlag *bool = nil
	VersionFlag *bool = nil
	// for RAS command line parameters
	servPort     *string = nil
	restPort     *string = nil
	RasTokenFlag *bool   = nil
	// for RAC command line parameters
	racServer   *string = nil
	racTestMode *bool   = nil
	// for HUB command line parameters
	hubServer *string = nil
	hubPort   *string = nil
)

type (
	dbConfig struct {
		host     string
		dbName   string
		user     string
		password string
		port     int
	}
	rasConfig struct {
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
		mgrStrategy      string
		authKeyFile      string
		changeTime       time.Time
		extractRules     entity.ExtractRules
		autoUpdateConfig entity.AutoUpdateConfig
	}
	racConfig struct {
		// for TPM chip
		eKeyCert     []byte
		iPriKeyFile  string
		iPriKey      []byte
		iPubKeyFile  string
		iPubKey      []byte
		iKeyCertFile string
		iKeyCert     []byte
		// for simulator test
		eKeyCertFileTest string
		eKeyCertTest     []byte
		iPriKeyFileTest  string
		iPriKeyTest      []byte
		iPubKeyFileTest  string
		iPubKeyTest      []byte
		iKeyCertFileTest string
		iKeyCertTest     []byte
		server           string
		testMode         bool
		hbDuration       time.Duration // heartbeat duration
		trustDuration    time.Duration // trust state duration
		clientId         int64
		password         string
		digestAlgorithm  string
	}
	hubConfig struct {
		server  string
		hubPort string
	}
	config struct {
		confType string
		dbConfig
		rasConfig
		racConfig
		hubConfig
	}
)

// InitRasFlags sets the ras server whole command flags.
func InitRasFlags() {
	servPort = pflag.StringP(RasPortLongFlag, RasPortShortFlag, "", RasPortHelp)
	restPort = pflag.StringP(RasRestPortLongFlag, RasRestPortShortFlag, "", RasRestHelp)
	VerboseFlag = pflag.BoolP(VerboseLongFlag, VerboseShortFlag, false, VerboseHelp)
	VersionFlag = pflag.BoolP(VersionLongFlag, VersionShortFlag, false, VersionHelp)
	RasTokenFlag = pflag.BoolP(RasTokenLongFlag, RasTokenShortFlag, false, RasTokenHelp)
}

// InitRacFlags sets the rac client whole command flags.
func InitRacFlags() {
	racServer = pflag.StringP(RacServerLongFlag, RacServerShortFlag, "", RacServerHelp)
	racTestMode = pflag.BoolP(RacTestModeLongFlag, RacTestModeShortFlag, false, RacTestModeHelp)
	VerboseFlag = pflag.BoolP(VerboseLongFlag, VerboseShortFlag, false, VerboseHelp)
	VersionFlag = pflag.BoolP(VersionLongFlag, VersionShortFlag, false, VersionHelp)
}

// InitRacFlags sets the rac client whole command flags.
func InitHubFlags() {
	hubServer = pflag.StringP(HubServerLongFlag, HubServerShortFlag, "", RacServerHelp)
	hubPort = pflag.StringP(HubPortLongFlag, HubPortShortFlag, "", HubPortHelp)
	VerboseFlag = pflag.BoolP(VerboseLongFlag, VerboseShortFlag, false, VerboseHelp)
	VersionFlag = pflag.BoolP(VersionLongFlag, VersionShortFlag, false, VersionHelp)
}

func SetupSignalHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		Save()
		os.Exit(0)
	}()
}

func getRootKeyCert(c *config) {
	var err error
	if c == nil {
		return
	}
	c.rasConfig.rootPrivKeyFile = viper.GetString(RasRootPrivKeyFile)
	if c.rasConfig.rootPrivKeyFile != NullString {
		c.rasConfig.rootPrivKey, _, err = pca.DecodePrivateKeyFromFile(c.rasConfig.rootPrivKeyFile)
		if err != nil {
			c.rasConfig.rootPrivKey = nil
			c.rasConfig.rootPrivKeyFile = NullString
		}
	} else {
		c.rasConfig.rootPrivKey = nil
	}
	c.rasConfig.rootKeyCertFile = viper.GetString(RasRootKeyCertFile)
	if c.rasConfig.rootKeyCertFile != NullString {
		c.rasConfig.rootKeyCert, _, err = pca.DecodeKeyCertFromFile(c.rasConfig.rootKeyCertFile)
		if err != nil {
			c.rasConfig.rootKeyCert = nil
			c.rasConfig.rootKeyCertFile = NullString
			c.rasConfig.rootPrivKey = nil
			c.rasConfig.rootPrivKeyFile = NullString
		}
	} else {
		c.rasConfig.rootKeyCert = nil
		c.rasConfig.rootPrivKey = nil
		c.rasConfig.rootPrivKeyFile = NullString
	}
	// if no loading root ca key/cert, create and self-signing one
	if c.rasConfig.rootPrivKey == nil {
		// modify pca.RootTemplate fields
		priv, _ := rsa.GenerateKey(rand.Reader, pca.RsaKeySize)
		// self signing
		certDer, err := x509.CreateCertificate(rand.Reader, &pca.RootTemplate, &pca.RootTemplate, &priv.PublicKey, priv)
		if err != nil {
			fmt.Println("couldn't create root key and certificate")
			return
		}
		c.rasConfig.rootKeyCert, err = x509.ParseCertificate(certDer)
		if err == nil {
			c.rasConfig.rootPrivKey = priv
			c.rasConfig.rootPrivKeyFile = RasRootKeyFileDefault + extKey
			c.rasConfig.rootKeyCertFile = RasRootKeyFileDefault + extCert
			pca.EncodePrivateKeyToFile(priv, c.rasConfig.rootPrivKeyFile)
			pca.EncodeKeyCertToFile(certDer, c.rasConfig.rootKeyCertFile)
		}
	}
}

func getPcaKeyCert(c *config) {
	var err error
	if c == nil {
		return
	}
	c.rasConfig.pcaPrivKeyFile = viper.GetString(RasPcaPrivKeyFile)
	if c.rasConfig.pcaPrivKeyFile != NullString {
		c.rasConfig.pcaPrivKey, _, err = pca.DecodePrivateKeyFromFile(c.rasConfig.pcaPrivKeyFile)
		if err != nil {
			c.rasConfig.pcaPrivKey = nil
			c.rasConfig.pcaPrivKeyFile = NullString
		}
	} else {
		c.rasConfig.pcaPrivKey = nil
	}
	c.rasConfig.pcaKeyCertFile = viper.GetString(RasPcaKeyCertFile)
	if c.rasConfig.pcaKeyCertFile != NullString {
		c.rasConfig.pcaKeyCert, _, err = pca.DecodeKeyCertFromFile(c.rasConfig.pcaKeyCertFile)
		if err != nil {
			c.rasConfig.pcaKeyCert = nil
			c.rasConfig.pcaKeyCertFile = NullString
			c.rasConfig.pcaPrivKey = nil
			c.rasConfig.pcaPrivKeyFile = NullString
		}
	} else {
		c.rasConfig.pcaKeyCert = nil
		c.rasConfig.pcaPrivKey = nil
		c.rasConfig.pcaPrivKeyFile = NullString
	}
	if c.rasConfig.pcaPrivKey == nil {
		// modify pca.PcaTemplate fields
		priv, _ := rsa.GenerateKey(rand.Reader, pca.RsaKeySize)
		// sign by root ca
		certDer, err := x509.CreateCertificate(rand.Reader, &pca.PcaTemplate, &pca.RootTemplate, &priv.PublicKey, c.rasConfig.rootPrivKey)
		if err != nil {
			fmt.Println("couldn't create pca ek key and certificate")
			return
		}
		c.rasConfig.pcaKeyCert, err = x509.ParseCertificate(certDer)
		if err == nil {
			c.rasConfig.pcaPrivKey = priv
			c.rasConfig.pcaPrivKeyFile = RasPcaKeyFileDefault + extKey
			c.rasConfig.pcaKeyCertFile = RasPcaKeyFileDefault + extCert
			pca.EncodePrivateKeyToFile(priv, c.rasConfig.pcaPrivKeyFile)
			pca.EncodeKeyCertToFile(certDer, c.rasConfig.pcaKeyCertFile)
		}
	}
}

func getServerConf(c *config) {
	if c == nil {
		return
	}
	c.dbConfig.host = viper.GetString(DbHost)
	c.dbConfig.dbName = viper.GetString(DbName)
	c.dbConfig.port = viper.GetInt(DbPort)
	c.dbConfig.user = viper.GetString(DbUser)
	c.dbConfig.password = viper.GetString(DbPassword)
	c.rasConfig.servPort = viper.GetString(RasPort)
	c.rasConfig.restPort = viper.GetString(RasRestPort)
	c.rasConfig.mgrStrategy = viper.GetString(RasMgrStrategy)
	c.rasConfig.authKeyFile = viper.GetString(RasAuthKeyFile)
	c.rasConfig.changeTime = viper.GetTime(RasChangeTime)
	var ers entity.ExtractRules
	if viper.UnmarshalKey(RasExtRules, &ers) == nil {
		c.rasConfig.extractRules = ers
	} else {
		c.rasConfig.extractRules = entity.ExtractRules{}
	}
	var auc entity.AutoUpdateConfig
	if viper.UnmarshalKey(RasAutoUpdateConfig, &auc) == nil {
		c.rasConfig.autoUpdateConfig = auc
	} else {
		c.rasConfig.autoUpdateConfig = entity.AutoUpdateConfig{}
	}
	c.racConfig.hbDuration = viper.GetDuration(RacHbDuration)
	c.racConfig.trustDuration = viper.GetDuration(RacTrustDuration)
	c.racConfig.digestAlgorithm = viper.GetString(RacDigestAlgorithm)
	// set command line input
	if servPort != nil && *servPort != "" {
		c.rasConfig.servPort = *servPort
	}
	if restPort != nil && *restPort != "" {
		c.rasConfig.restPort = *restPort
	}
	getRootKeyCert(c)
	getPcaKeyCert(c)
}

func getClientEKeyCertTest(c *config) {
	var err error
	if c == nil {
		return
	}
	c.racConfig.eKeyCertFileTest = viper.GetString(RacEKeyCertFileTest)
	if c.racConfig.eKeyCertFileTest != NullString {
		_, c.racConfig.eKeyCertTest, err = pca.DecodeKeyCertFromFile(c.racConfig.eKeyCertFileTest)
		if err != nil {
			c.racConfig.eKeyCertTest = nil
			c.racConfig.eKeyCertFileTest = NullString
		}
	} else {
		c.racConfig.eKeyCertTest = nil
	}
}

func getClientIKeyCertTest(c *config) {
	var err error
	if c == nil {
		return
	}
	c.racConfig.iPriKeyFileTest = viper.GetString(RacIPriKeyFileTest)
	if c.racConfig.iPriKeyFileTest != NullString {
		c.racConfig.iPriKeyTest, err = ioutil.ReadFile(c.racConfig.iPriKeyFileTest)
		if err != nil {
			c.racConfig.iPriKeyTest = nil
			c.racConfig.iPriKeyFileTest = NullString
		}
	} else {
		c.racConfig.iPriKeyTest = nil
	}
	c.racConfig.iPubKeyFileTest = viper.GetString(RacIPubKeyFileTest)
	if c.racConfig.iPubKeyFileTest != NullString {
		c.racConfig.iPubKeyTest, err = ioutil.ReadFile(c.racConfig.iPubKeyFileTest)
		if err != nil {
			c.racConfig.iPubKeyTest = nil
			c.racConfig.iPubKeyFileTest = NullString
		}
	} else {
		c.racConfig.iPubKeyTest = nil
	}
	c.racConfig.iKeyCertFileTest = viper.GetString(RacIKeyCertFileTest)
	if c.racConfig.iKeyCertFileTest != NullString {
		_, c.racConfig.iKeyCertTest, err = pca.DecodeKeyCertFromFile(c.racConfig.iKeyCertFileTest)
		if err != nil {
			c.racConfig.iKeyCertTest = nil
			c.racConfig.iKeyCertFileTest = NullString
			c.racConfig.iPriKeyTest = nil
			c.racConfig.iPriKeyFileTest = NullString
			c.racConfig.iPubKeyTest = nil
			c.racConfig.iPubKeyFileTest = NullString
		}
	} else {
		c.racConfig.iKeyCertTest = nil
		c.racConfig.iPriKeyTest = nil
		c.racConfig.iPriKeyFileTest = NullString
		c.racConfig.iPubKeyTest = nil
		c.racConfig.iPubKeyFileTest = NullString
	}
}

func getClientIKeyCert(c *config) {
	var err error
	if c == nil {
		return
	}
	c.racConfig.iPriKeyFile = viper.GetString(RacIPriKeyFile)
	if c.racConfig.iPriKeyFile != NullString {
		c.racConfig.iPriKey, err = ioutil.ReadFile(c.racConfig.iPriKeyFile)
		if err != nil {
			c.racConfig.iPriKey = nil
			c.racConfig.iPriKeyFile = NullString
		}
	} else {
		c.racConfig.iPriKey = nil
	}
	c.racConfig.iPubKeyFile = viper.GetString(RacIPubKeyFile)
	if c.racConfig.iPubKeyFile != NullString {
		c.racConfig.iPubKey, err = ioutil.ReadFile(c.racConfig.iPubKeyFile)
		if err != nil {
			c.racConfig.iPubKey = nil
			c.racConfig.iPubKeyFile = NullString
		}
	} else {
		c.racConfig.iPubKey = nil
	}
	c.racConfig.iKeyCertFile = viper.GetString(RacIKeyCertFile)
	if c.racConfig.iKeyCertFile != NullString {
		_, c.racConfig.iKeyCert, err = pca.DecodeKeyCertFromFile(c.racConfig.iKeyCertFile)
		if err != nil {
			c.racConfig.iKeyCert = nil
			c.racConfig.iKeyCertFile = NullString
			c.racConfig.iPriKey = nil
			c.racConfig.iPriKeyFile = NullString
			c.racConfig.iPubKey = nil
			c.racConfig.iPubKeyFile = NullString
		}
	} else {
		c.racConfig.iKeyCert = nil
		c.racConfig.iPriKey = nil
		c.racConfig.iPriKeyFile = NullString
		c.racConfig.iPubKey = nil
		c.racConfig.iPubKeyFile = NullString
	}
}

func getClientConf(c *config) {
	if c == nil {
		return
	}
	c.racConfig.server = viper.GetString(RacServer)
	c.racConfig.hbDuration = viper.GetDuration(RacHbDuration)
	c.racConfig.trustDuration = viper.GetDuration(RacTrustDuration)
	c.racConfig.clientId = viper.GetInt64(RacClientId)
	c.racConfig.password = viper.GetString(RacPassword)
	c.racConfig.digestAlgorithm = viper.GetString(RacDigestAlgorithm)
	// set command line input
	if racServer != nil && *racServer != "" {
		c.racConfig.server = *racServer
	}
	if racTestMode != nil {
		c.racConfig.testMode = *racTestMode
	}
	if c.racConfig.testMode {
		// in test mode, load EK/IK and certificate from files
		// because simulator couldn't save them.
		getClientEKeyCertTest(c)
		getClientIKeyCertTest(c)
	} else {
		// in TPM only load IK/IC
		getClientIKeyCert(c)
	}
}

func getHubConf(c *config) {
	if c == nil {
		return
	}
	c.hubConfig.server = viper.GetString(HubServer)
	c.hubConfig.hubPort = viper.GetString(HubPort)
	// set command line input
	if hubServer != nil && *hubServer != "" {
		c.hubConfig.server = *hubServer
	}
	if hubPort != nil && *hubPort != "" {
		c.hubConfig.hubPort = *hubPort
	}
}

// setConfigPaths sets the config paths for different apps
func setConfigPaths(cfg *config) *config {
	var s string
	viper.SetConfigName(ConfName)
	viper.SetConfigType(ConfExt)
	switch cfg.confType {
	case ConfServer:
		for _, s = range defaultRasConfigPath {
			viper.AddConfigPath(s)
		}
	case ConfClient:
		for _, s = range defaultRacConfigPath {
			viper.AddConfigPath(s)
		}
	case ConfHub:
		for _, s = range defaultRahubConfigPath {
			viper.AddConfigPath(s)
		}
	}
	return cfg
}

// setConfigDefaults sets default configurations for different apps
func setConfigDefaults(cfg *config) *config {
	switch cfg.confType {
	case ConfServer:
	case ConfClient:
		viper.SetDefault(RacHbDuration, RacDefaultHbDuration)
		viper.SetDefault(RacTrustDuration, RacDefaultTrustDuration)
		viper.SetDefault(RacClientId, RacNullClientId)
		viper.SetDefault(RacPassword, RacDefaultPassword)
		viper.SetDefault(RacDigestAlgorithm, RacDigestAlgorithmSHA256)
	case ConfHub:
	}
	return cfg
}

func loadConfig(cfg *config) *config {
	switch cfg.confType {
	case ConfServer:
		getServerConf(cfg)
	case ConfClient:
		getClientConf(cfg)
	case ConfHub:
		getHubConf(cfg)
	}
	return cfg
}

/*
GetDefault returns the global default config object.
It searches the defaultConfigPath to find the first matched config.yaml.
if it doesn't find any one, it returns the default values by code.
Notice:
  server must has a config.yaml to give the configuration.
  client may not have one.
*/
func GetDefault(cfType string) *config {
	if confG != nil {
		return confG
	}

	confG = &config{}
	confG.confType = strings.ToLower(cfType)
	confG = setConfigPaths(confG)
	confG = setConfigDefaults(confG)

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf("read config file error: %v\n", err)
	}
	confG = loadConfig(confG)
	return confG
}

func saveRasConfig(cfg *config) {
	viper.Set(DbHost, cfg.dbConfig.host)
	viper.Set(DbName, cfg.dbConfig.dbName)
	viper.Set(DbPort, cfg.dbConfig.port)
	viper.Set(DbUser, cfg.dbConfig.user)
	viper.Set(DbPassword, cfg.dbConfig.password)
	viper.Set(RasRootPrivKeyFile, cfg.rasConfig.rootPrivKeyFile)
	viper.Set(RasRootKeyCertFile, cfg.rasConfig.rootKeyCertFile)
	viper.Set(RasPcaPrivKeyFile, cfg.rasConfig.pcaPrivKeyFile)
	viper.Set(RasPcaKeyCertFile, cfg.rasConfig.pcaKeyCertFile)
	viper.Set(RasPort, cfg.rasConfig.servPort)
	viper.Set(RasRestPort, cfg.rasConfig.restPort)
	viper.Set(RasMgrStrategy, cfg.rasConfig.mgrStrategy)
	viper.Set(RasAuthKeyFile, cfg.rasConfig.authKeyFile)
	viper.Set(RasChangeTime, cfg.rasConfig.changeTime)
	viper.Set(RasAutoUpdateConfig, cfg.rasConfig.autoUpdateConfig)
	// store common configuration for all client
	viper.Set(RacHbDuration, cfg.racConfig.hbDuration)
	viper.Set(RacTrustDuration, cfg.racConfig.trustDuration)
	viper.Set(RacDigestAlgorithm, cfg.racConfig.digestAlgorithm)
}

func saveRacConfig(cfg *config) {
	// store common part
	if cfg.racConfig.testMode {
		viper.Set(RacEKeyCertFileTest, cfg.racConfig.eKeyCertFileTest)
		viper.Set(RacIPriKeyFileTest, cfg.racConfig.iPriKeyFileTest)
		viper.Set(RacIPubKeyFileTest, cfg.racConfig.iPubKeyFileTest)
		viper.Set(RacIKeyCertFileTest, cfg.racConfig.iKeyCertFileTest)
	} else {
		viper.Set(RacIPriKeyFile, cfg.racConfig.iPriKeyFile)
		viper.Set(RacIPubKeyFile, cfg.racConfig.iPubKeyFile)
		viper.Set(RacIKeyCertFile, cfg.racConfig.iKeyCertFile)
	}
	viper.Set(RacServer, cfg.racConfig.server)
	viper.Set(RacHbDuration, cfg.racConfig.hbDuration)
	viper.Set(RacTrustDuration, cfg.racConfig.trustDuration)
	viper.Set(RacDigestAlgorithm, cfg.racConfig.digestAlgorithm)
	// store special configuration for this client
	viper.Set(RacClientId, cfg.racConfig.clientId)
	viper.Set(RacPassword, cfg.racConfig.password)
}

func saveRahubConfig(cfg *config) {
	viper.Set(HubServer, cfg.hubConfig.server)
	viper.Set(HubPort, cfg.hubConfig.hubPort)
}

// Save saves all config variables to the config.yaml file.
func Save() {
	if confG != nil {
		switch confG.confType {
		case ConfServer:
			saveRasConfig(confG)
		case ConfClient:
			saveRacConfig(confG)
		case ConfHub:
			saveRahubConfig(confG)
		}
		err := viper.WriteConfig()
		if err != nil {
			_ = viper.SafeWriteConfig()
		}
	}
}

// for dbConfig handle

func (c *config) GetHost() string {
	return c.dbConfig.host
}

func (c *config) SetHost(host string) {
	c.dbConfig.host = host
}

func (c *config) GetDBName() string {
	return c.dbConfig.dbName
}

func (c *config) SetDBName(dbName string) {
	c.dbConfig.dbName = dbName
}

func (c *config) GetDBPort() int {
	return c.dbConfig.port
}

func (c *config) SetDBPort(port int) {
	c.dbConfig.port = port
}

func (c *config) GetUser() string {
	return c.dbConfig.user
}

func (c *config) SetUser(user string) {
	c.dbConfig.user = user
}

func (c *config) GetPassword() string {
	return c.dbConfig.password
}

func (c *config) SetPassword(password string) {
	c.dbConfig.password = password
}

// for rasConfig handle

func (c *config) GetMgrStrategy() string {
	return c.rasConfig.mgrStrategy
}

func (c *config) SetMgrStrategy(s string) {
	c.rasConfig.mgrStrategy = s
	c.rasConfig.changeTime = time.Now()
}

func (c *config) GetChangeTime() time.Time {
	return c.rasConfig.changeTime
}

func (c *config) SetExtractRules(e entity.ExtractRules) {
	c.rasConfig.extractRules = e
}

func (c *config) GetExtractRules() entity.ExtractRules {
	return c.rasConfig.extractRules
}

func (c *config) SetAutoUpdateConfig(a entity.AutoUpdateConfig) {
	c.rasConfig.autoUpdateConfig = a
}

func (c *config) GetAutoUpdateConfig() entity.AutoUpdateConfig {
	return c.rasConfig.autoUpdateConfig
}

func (c *config) GetPort() string {
	return c.rasConfig.servPort
}

func (c *config) GetRestPort() string {
	return c.rasConfig.restPort
}

func (c *config) GetRootPrivateKey() crypto.PrivateKey {
	return c.rasConfig.rootPrivKey
}

func (c *config) GetRootKeyCert() *x509.Certificate {
	return c.rasConfig.rootKeyCert
}

func (c *config) GetPcaPrivateKey() crypto.PrivateKey {
	return c.rasConfig.pcaPrivKey
}

func (c *config) GetPcaKeyCert() *x509.Certificate {
	return c.rasConfig.pcaKeyCert
}

func (c *config) GetAuthKeyFile() string {
	return c.rasConfig.authKeyFile
}

func (c *config) SetAuthKeyFile(filename string) {
	c.rasConfig.authKeyFile = filename
}

// for racConfig handle

func (c *config) GetEKeyCert() []byte {
	return c.racConfig.eKeyCert
}

func (c *config) SetEKeyCert(ec []byte) {
	c.racConfig.eKeyCert = ec
}

func (c *config) GetIPriKey() []byte {
	return c.racConfig.iPriKey
}

func (c *config) SetIPriKey(ikDer []byte) {
	c.racConfig.iPriKey = ikDer
	c.racConfig.iPriKeyFile = RacIPriKeyFileDefault + extKey
	ioutil.WriteFile(c.racConfig.iPriKeyFile, ikDer, 0600)
}

func (c *config) GetIPubKey() []byte {
	return c.racConfig.iPubKey
}

func (c *config) SetIPubKey(ikDer []byte) {
	c.racConfig.iPubKey = ikDer
	c.racConfig.iPubKeyFile = RacIPubKeyFileDefault + extKey
	ioutil.WriteFile(c.racConfig.iPubKeyFile, ikDer, 0600)
}

func (c *config) GetIKeyCert() []byte {
	return c.racConfig.iKeyCert
}

func (c *config) SetIKeyCert(icDer []byte) {
	c.racConfig.iKeyCert = icDer
	c.racConfig.iKeyCertFile = RacIKeyCertFileDefault + extCert
	pca.EncodeKeyCertToFile(icDer, c.racConfig.iKeyCertFile)
}

func (c *config) GetEKeyCertTest() []byte {
	return c.racConfig.eKeyCertTest
}

func (c *config) SetEKeyCertTest(ecDer []byte) {
	c.racConfig.eKeyCertTest = ecDer
	c.racConfig.eKeyCertFileTest = RacEKFileDefaultTest + extCert
	pca.EncodeKeyCertToFile(ecDer, c.racConfig.eKeyCertFileTest)
}

func (c *config) GetIPriKeyTest() []byte {
	return c.racConfig.iPriKeyTest
}

func (c *config) SetIPriKeyTest(ikDer []byte) {
	c.racConfig.iPriKeyTest = ikDer
	c.racConfig.iPriKeyFileTest = RacIPriKeyFileDefaultTest + extKey
	ioutil.WriteFile(c.racConfig.iPriKeyFileTest, ikDer, 0600)
}

func (c *config) GetIPubKeyTest() []byte {
	return c.racConfig.iPubKeyTest
}

func (c *config) SetIPubKeyTest(ikDer []byte) {
	c.racConfig.iPubKeyTest = ikDer
	c.racConfig.iPubKeyFileTest = RacIPubKeyFileDefaultTest + extKey
	ioutil.WriteFile(c.racConfig.iPubKeyFileTest, ikDer, 0600)
}

func (c *config) GetIKeyCertTest() []byte {
	return c.racConfig.iKeyCertTest
}

func (c *config) SetIKeyCertTest(icDer []byte) {
	c.racConfig.iKeyCertTest = icDer
	c.racConfig.iKeyCertFileTest = RacIKeyCertFileDefaultTest + extCert
	pca.EncodeKeyCertToFile(icDer, c.racConfig.iKeyCertFileTest)
}

func (c *config) GetServer() string {
	return c.racConfig.server
}

func (c *config) GetTestMode() bool {
	return c.racConfig.testMode
}

func (c *config) GetTrustDuration() time.Duration {
	return c.racConfig.trustDuration
}

func (c *config) SetTrustDuration(d time.Duration) {
	c.racConfig.trustDuration = d
}

func (c *config) GetHBDuration() time.Duration {
	return c.racConfig.hbDuration
}

func (c *config) SetHBDuration(d time.Duration) {
	c.racConfig.hbDuration = d
}

func (c *config) GetClientId() int64 {
	return c.racConfig.clientId
}

func (c *config) SetClientId(id int64) {
	c.racConfig.clientId = id
}

func (c *config) GetDigestAlgorithm() string {
	return c.racConfig.digestAlgorithm
}

func (c *config) SetDigestAlgorithm(algorithm string) {
	c.racConfig.digestAlgorithm = algorithm
}

// for hubConfig handle

func (c *config) GetHubServer() string {
	return c.hubConfig.server
}

func (c *config) GetHubPort() string {
	return c.hubConfig.hubPort
}

// Logf controls the log.Printf output with VerboseFlag
func Logf(format string, v ...interface{}) {
	if *VerboseFlag {
		log.Printf(format, v...)
	}
}
