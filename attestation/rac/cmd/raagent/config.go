/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.
*/

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// path
	strLocalConf = "."
	strHomeConf  = "$HOME/.config/attestation/rac"
	strSysConf   = "/etc/attestation/rac"
	// config file name
	confName = "config"
	confExt  = "yaml"
	// logger
	logPath = "log.path"
	// raagent config key
	confClientID        = "racconfig.clientid"
	confServer          = "racconfig.server"
	confHbDuration      = "racconfig.hbduration"
	confTrustDuration   = "racconfig.trustduration"
	confPassword        = "racconfig.password"
	confEKeyCert        = "racconfig.ecfile"
	confIKeyCert        = "racconfig.icfile"
	confEKeyCertTest    = "racconfig.ectestfile"
	confIKeyCertTest    = "racconfig.ictestfile"
	confDigestAlgorithm = "racconfig.digestalgorithm"
	confSeed            = "racconfig.seed"
	// raagent config default value
	nullString         = ""
	logFile            = "./rac-log.txt"
	keyExt             = ".key"
	crtExt             = ".crt"
	ekCert             = "./ec"
	ikCert             = "./ic"
	ekCertTest         = "./ectest"
	ikCertTest         = "./ictest"
	confNullSeed       = -1
	defaultTestMode    = false
	defaultVerboseMode = false
	defaultDigestAlg   = "sha1"
	defaultImaLog      = "./ascii_runtime_measurements"
	defaultBiosLog     = "./binary_bios_measurements"
	// ras server listen ip:port
	lflagServer = "server"
	sflagServer = "s"
	helpServer  = "ras serves at IP:PORT"
	// test mode switcher
	lflagTest = "test"
	sflagTest = "t"
	helpTest  = "run in test mode[true] or not[false/default]"
	// version output
	lflagVersion = "version"
	sflagVersion = "V"
	helpVersion  = "show version number and quit"
	// verbose output
	lflagVerbose = "verbose"
	sflagVerbose = "v"
	helpVerbose  = "show running debug information"
	// digest alg output
	//lflagAlg = "algorithm"
	//sflagAlg = "a"
	//helpAlg  = "input sha1 sha256 or sm3"
	// ima log path for testing mode
	lflagIma = "imalog"
	sflagIma = "i"
	helpIma  = "input ima log path"
	// digest alg output
	lflagBios = "bioslog"
	sflagBios = "b"
	helpBios  = "input bios log path"
)

type (
	racConfig struct {
		clientId      int64
		server        string
		hbDuration    time.Duration // heartbeat duration
		trustDuration time.Duration // trust state duration
		logPath       string
		digest        string
		testMode      bool
		eKeyCert      []byte
		iKeyCert      []byte

		// for TPM chip
		password string
		ecFile   string
		icFile   string
		// for simulator test
		eKeyCertTest []byte
		iKeyCertTest []byte
		ecTestFile   string
		icTestFile   string
		seed         int64
	}
)

var (
	defaultPaths = []string{
		strLocalConf,
		strHomeConf,
		strSysConf,
	}
	racCfg      *racConfig
	server      *string = nil
	testMode    *bool   = nil
	versionFlag *bool   = nil
	verboseFlag *bool   = nil
	//algDigest   *string = nil
	imaLogPath  *string = nil
	biosLogPath *string = nil
)

// initFlags inits the raagent whole command flags.
func initFlags() {
	server = pflag.StringP(lflagServer, sflagServer, nullString, helpServer)
	testMode = pflag.BoolP(lflagTest, sflagTest, defaultTestMode, helpTest)
	versionFlag = pflag.BoolP(lflagVersion, sflagVersion, false, helpVersion)
	verboseFlag = pflag.BoolP(lflagVerbose, sflagVerbose, defaultVerboseMode, helpVerbose)
	//algDigest = pflag.StringP(lflagAlg, sflagAlg, defaultDigestAlg, helpAlg)
	imaLogPath = pflag.StringP(lflagIma, sflagIma, defaultImaLog, helpIma)
	biosLogPath = pflag.StringP(lflagBios, sflagBios, defaultBiosLog, helpBios)
	pflag.Parse()
}

// signalHandler handles the singal and save configurations.
func signalHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		saveConfigs()
		os.Exit(0)
	}()
}

func handleFlags() {
	if versionFlag != nil && *versionFlag {
		fmt.Printf("raagent: %s\n", raagentVersion)
		os.Exit(0)
	}
	// init logger
	if verboseFlag != nil && *verboseFlag {
		logger.L = logger.NewDebugLogger(GetLogPath())
	} else {
		logger.L = logger.NewInfoLogger(GetLogPath())
	}
	// set command line input
	if server != nil && *server != nullString {
		SetServer(*server)
	}
	/*if algDigest != nil && *algDigest != nullString {
		SetDigestAlgorithm(*algDigest)
	}*/
	if testMode != nil && *testMode {
		// in test mode, load EK/IK and their certificate from files
		// because simulator couldn't save them after restart.
		SetTestMode(*testMode)
		getEKCertTest()
		getIKCertTest()

	} else {
		// for TPM hardware, only load IK/IC
		getEKCert()
		getIKCert()
	}
}

// getEKCertTest returns the raagent DER format EK certificate for test.
func getEKCertTest() {
	var err error
	if racCfg == nil {
		return
	}
	racCfg.ecTestFile = viper.GetString(confEKeyCertTest)
	if racCfg.ecTestFile != nullString {
		_, racCfg.eKeyCertTest, err = cryptotools.DecodeKeyCertFromFile(racCfg.ecTestFile)
		if err != nil {
			racCfg.eKeyCertTest = []byte{}
			// racCfg.ecTestFile = ekCertTest + crtExt
		}
	} else {
		racCfg.ecTestFile = ekCertTest + crtExt
	}
}

// getIKCertTest returns the raagent DER format IK certificate for test.
func getIKCertTest() {
	var err error
	if racCfg == nil {
		return
	}
	racCfg.icTestFile = viper.GetString(confIKeyCertTest)
	if racCfg.icTestFile != nullString {
		_, racCfg.iKeyCertTest, err = cryptotools.DecodeKeyCertFromFile(racCfg.icTestFile)
		if err != nil {
			racCfg.iKeyCertTest = []byte{}
			// racCfg.icTestFile = ikCertTest + crtExt
		}
	} else {
		racCfg.icTestFile = ikCertTest + crtExt
	}
}

func getEKCert() {
	var err error
	if racCfg == nil {
		return
	}
	racCfg.ecFile = viper.GetString(confEKeyCert)
	if racCfg.ecFile != nullString {
		_, racCfg.eKeyCert, err = cryptotools.DecodeKeyCertFromFile(racCfg.ecFile)
		if err != nil {
			racCfg.eKeyCert = []byte{}
			// racCfg.ecFile = ekCert + crtExt
		}
	} else {
		racCfg.ecFile = ekCert + crtExt
	}
}

func getIKCert() {
	var err error
	if racCfg == nil {
		return
	}
	racCfg.icFile = viper.GetString(confIKeyCert)
	if racCfg.icFile != nullString {
		_, racCfg.iKeyCert, err = cryptotools.DecodeKeyCertFromFile(racCfg.icFile)
		if err != nil {
			racCfg.iKeyCert = []byte{}
			// racCfg.icFile = ikCert + crtExt
		}
	} else {
		racCfg.icFile = ikCert + crtExt
	}
}

// loadConfigs searches and loads config from config.yaml file.
func loadConfigs() {
	if racCfg != nil {
		return
	}
	// set default values
	racCfg = &racConfig{}
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
	racCfg.logPath = viper.GetString(logPath)
	racCfg.server = viper.GetString(confServer)
	racCfg.hbDuration = viper.GetDuration(confHbDuration)
	racCfg.trustDuration = viper.GetDuration(confTrustDuration)
	racCfg.clientId = viper.GetInt64(confClientID)
	racCfg.password = viper.GetString(confPassword)
	racCfg.digest = viper.GetString(confDigestAlgorithm)
	racCfg.seed = viper.GetInt64(confSeed)
}

// saveConfigs saves all config variables to the config.yaml file.
func saveConfigs() {
	if racCfg == nil {
		return
	}
	viper.Set(logPath, racCfg.logPath)
	viper.Set(confServer, racCfg.server)
	viper.Set(confClientID, racCfg.clientId)
	viper.Set(confPassword, racCfg.password)
	viper.Set(confHbDuration, racCfg.hbDuration)
	viper.Set(confTrustDuration, racCfg.trustDuration)
	viper.Set(confDigestAlgorithm, racCfg.digest)
	viper.Set(confSeed, racCfg.seed)
	if racCfg.testMode {
		viper.Set(confEKeyCertTest, racCfg.ecTestFile)
		viper.Set(confIKeyCertTest, racCfg.icTestFile)
		err := cryptotools.EncodeKeyCertToFile(racCfg.eKeyCertTest, racCfg.ecTestFile)
		if err != nil {
			racCfg.ecTestFile = ekCertTest + crtExt
			cryptotools.EncodeKeyCertToFile(racCfg.eKeyCertTest, racCfg.ecTestFile)
		}
		err = cryptotools.EncodeKeyCertToFile(racCfg.iKeyCertTest, racCfg.icTestFile)
		if err != nil {
			racCfg.icTestFile = ikCertTest + crtExt
			cryptotools.EncodeKeyCertToFile(racCfg.iKeyCertTest, racCfg.icTestFile)
		}
	} else {
		viper.Set(confEKeyCert, racCfg.ecFile)
		viper.Set(confIKeyCert, racCfg.icFile)
		err := cryptotools.EncodeKeyCertToFile(racCfg.eKeyCert, racCfg.ecFile)
		if err != nil {
			racCfg.ecFile = ekCert + crtExt
			cryptotools.EncodeKeyCertToFile(racCfg.eKeyCert, racCfg.ecFile)
		}
		err = cryptotools.EncodeKeyCertToFile(racCfg.iKeyCert, racCfg.icFile)
		if err != nil {
			racCfg.icFile = ikCert + crtExt
			cryptotools.EncodeKeyCertToFile(racCfg.iKeyCert, racCfg.icFile)
		}
	}
	err := viper.WriteConfig()
	if err != nil {
		_ = viper.SafeWriteConfig()
	}
}

// GetEKeyCert returns the raagent DER format EK certificate.
func GetEKeyCert() []byte {
	if racCfg == nil {
		return []byte{}
	}
	if GetTestMode() {
		return racCfg.eKeyCertTest
	} else {
		return racCfg.eKeyCert
	}
}

// SetEKeyCert sets the raagent DER format EK certificate.
func SetEKeyCert(ec []byte) {
	if racCfg == nil {
		return
	}
	if GetTestMode() {
		racCfg.eKeyCertTest = ec
	} else {
		racCfg.eKeyCert = ec
	}
}

// GetIKeyCert returns the raagent DER format IK certificate.
func GetIKeyCert() []byte {
	if racCfg == nil {
		return []byte{}
	}
	if GetTestMode() {
		return racCfg.iKeyCertTest
	} else {
		return racCfg.iKeyCert
	}
}

// SetIKeyCert sets the raagent DER format IK certificate.
func SetIKeyCert(ic []byte) {
	if racCfg == nil {
		return
	}
	if GetTestMode() {
		racCfg.iKeyCertTest = ic
	} else {
		racCfg.iKeyCert = ic
	}
}

// GetClientId returns the raagent client id configuration.
func GetClientId() int64 {
	if racCfg == nil {
		return -1
	}
	return racCfg.clientId
}

// SetClientId sets the raagent client id configuration.
func SetClientId(id int64) {
	if racCfg == nil {
		return
	}
	racCfg.clientId = id
}

// GetLogPath returns the logger path configuration.
func GetLogPath() string {
	if racCfg == nil {
		return logFile
	}
	return racCfg.logPath
}

// GetServer returns the ras server listening ip:port configuration.
func GetServer() string {
	if racCfg == nil {
		return ""
	}
	return racCfg.server
}

// SetServer sets the ras server listening ip:port configuration.
func SetServer(s string) {
	if racCfg == nil {
		return
	}
	racCfg.server = s
}

// GetTestMode returns the test mode configuration.
func GetTestMode() bool {
	if racCfg == nil {
		return false
	}
	return racCfg.testMode
}

// SetTestMode sets the test mode configuration.
func SetTestMode(m bool) {
	if racCfg == nil {
		return
	}
	racCfg.testMode = m
}

// GetHBDuration returns the heart beat duration configuration.
func GetHBDuration() time.Duration {
	if racCfg == nil {
		return 0
	}
	return racCfg.hbDuration
}

// SetHBDuration sets the heart beat duration configuration.
func SetHBDuration(d time.Duration) {
	if racCfg == nil {
		return
	}
	racCfg.hbDuration = d
}

// GetTrustDuration returns the trust report expire duration configuration.
func GetTrustDuration() time.Duration {
	if racCfg == nil {
		return 0
	}
	return racCfg.trustDuration
}

// SetTrustDuration sets the trust report expire duration configuration.
func SetTrustDuration(d time.Duration) {
	if racCfg == nil {
		return
	}
	racCfg.trustDuration = d
}

// GetDigestAlgorithm returns the digest algorithm configuration.
func GetDigestAlgorithm() string {
	if racCfg == nil {
		return ""
	}
	return racCfg.digest
}

// SetDigestAlgorithm sets the digest algorithm configuration.
func SetDigestAlgorithm(algorithm string) {
	if racCfg == nil {
		return
	}
	racCfg.digest = algorithm
}

// GetSeed returns the tpm-simulator seed configuration.
func GetSeed() int64 {
	if racCfg == nil {
		return 0
	}
	return racCfg.seed
}

// SetSeed sets the tpm-simulator seed configuration.
func SetSeed(seed int64) {
	if racCfg == nil {
		return
	}
	racCfg.seed = seed
}

// GetImaLogPath gets the ima log path configuration for testing mode.
func GetImaLogPath() string {
	if imaLogPath == nil {
		return ""
	}
	return *imaLogPath
}

// GetBiosLogPath gets the bios log path configuration for testing mode.
func GetBiosLogPath() string {
	if biosLogPath == nil {
		return ""
	}
	return *biosLogPath
}
