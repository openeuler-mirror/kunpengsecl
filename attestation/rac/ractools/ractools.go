/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: jiayunhao
Create: 2021-09-17
Description: Define the structure for the TPM operation.
*/

package ractools

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qapi"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	//   on TCG EK Credential Profile For TPM Family 2.0
	//   Level 0 Version 2.4 Revision 3
	//   https://trustedcomputinggroup.org/resource/tcg-ek-credential-profile-for-tpm-family-2-0/
	//      0x01C00002      RSA 2048 EK Certificate
	//      0x01C00003      RSA 2048 EK Nonce
	//      0x01C00004      RSA 2048 EK Template
	//      0x01C0000A      ECC NIST P256 EK Certificate
	//      0x01C0000B      ECC NIST P256 EK Nonce
	//      0x01C0000C      ECC NIST P256 EK Template
	//      0x01C00012      RSA 2048 EK Certificate (H-1)
	//      0x01C00014      ECC NIST P256 EK Certificate (H-2)
	//      0x01C00016      ECC NIST P384 EK Certificate (H-3)
	//      0x01C00018      ECC NIST P512 EK Certificate (H-4)
	//      0x01C0001A      ECC SM2_P256 EK Certificate (H-5)
	//      0x01C0001C      RSA 3072 EK Certificate (H-6)
	//      0x01C0001E      RSA 4096 EK Certificate (H-7)
	// IndexRsa2048EKCert means RSA 2048 EK Certificate index
	IndexRsa2048EKCert uint32 = 0x01C00002
	// IndexRsa2048EKNonce means RSA 2048 EK Nonce index
	IndexRsa2048EKNonce uint32 = 0x01C00003
	// IndexRsa2048EKTemplate means RSA 2048 EK Template index
	IndexRsa2048EKTemplate uint32 = 0x01C00004
	// IndexECCP256EKCert means ECC NIST P256 EK Certificate index
	IndexECCP256EKCert uint32 = 0x01C0000A
	// IndexECCP256EKNonce means ECC NIST P256 EK Nonce index
	IndexECCP256EKNonce uint32 = 0x01C0000B
	// IndexECCP256EKTemplate means ECC NIST P256 EK Template index
	IndexECCP256EKTemplate uint32 = 0x01C0000C
	// IndexRsa2048EKCertH1 means RSA 2048 EK Certificate (H-1) index
	IndexRsa2048EKCertH1 uint32 = 0x01C00012
	// IndexECCP256EKCertH2 means ECC NIST P256 EK Certificate (H-2) index
	IndexECCP256EKCertH2 uint32 = 0x01C00014
	// IndexECCP384EKCertH3 means ECC NIST P384 EK Certificate (H-3) index
	IndexECCP384EKCertH3 uint32 = 0x01C00016
	// IndexECCP512EKCertH4 means ECC NIST P512 EK Certificate (H-4) index
	IndexECCP512EKCertH4 uint32 = 0x01C00018
	// IndexSM2P256EKCertH5 means ECC SM2_P256 EK Certificate (H-5) index
	IndexSM2P256EKCertH5 uint32 = 0x01C0001A
	// IndexRsa3072EKCertH6 means RSA 3072 EK Certificate (H-6) index
	IndexRsa3072EKCertH6 uint32 = 0x01C0001C
	// IndexRsa4096EKCertH7 means RSA 4096 EK Certificate (H-7) index
	IndexRsa4096EKCertH7 uint32 = 0x01C0001E

	tpmDevPath1  = "/dev/tpmrm0"
	tpmDevPath2  = "/dev/tpm0"
	blockSize    = 1024
	constDMIBIOS = `# dmidecode 3.2
Getting SMBIOS data from sysfs.
SMBIOS 2.7 present.

Handle 0x0000, DMI type 0, 24 bytes
BIOS Information
	Vendor: American Megatrends Inc.
	Version: 4.6.5
	Release Date: 09/26/2013
	Address: 0xF0000
	Runtime Size: 64 kB
	ROM Size: 4096 kB
	Characteristics:
		PCI is supported
		BIOS is upgradeable
		BIOS shadowing is allowed
		Boot from CD is supported
		Selectable boot is supported
		EDD is supported
		Print screen service is supported (int 5h)
		8042 keyboard services are supported (int 9h)
		Printer services are supported (int 17h)
		ACPI is supported
		USB legacy is supported
		BIOS boot specification is supported
		Targeted content distribution is supported
		UEFI is supported
	BIOS Revision: 4.6`
	constDMISYSTEM = `# dmidecode 3.2
Getting SMBIOS data from sysfs.
SMBIOS 2.7 present.

Handle 0x0001, DMI type 1, 27 bytes
System Information
	Manufacturer: Hasee Computer
	Product Name: CW35S
	Version: Not Applicable
	Serial Number: Not Applicable
	UUID: f0f59000-7a0a-0000-0000-000000000000
	Wake-up Type: Power Switch
	SKU Number: Not Applicable
	Family: Not Applicable`

	emptyPassword = ""
	talistpath    = "./talist"
	// TestImaLogPath means the path to the test case ima log
	TestImaLogPath = "./ascii_runtime_measurements"
	// TestBiosLogPath means the path to the test case bios log
	TestBiosLogPath = "./binary_bios_measurements"
	// TestSeedPath means the path to the test case seed
	TestSeedPath = "./simulator_seed"
	// ImaLogPath means the path to the ima log
	ImaLogPath = "/sys/kernel/security/ima/ascii_runtime_measurements"
	// BiosLogPath means the path to the bios log
	BiosLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements"
	// AlgSM3 means the code name of the SM3 algorithm
	AlgSM3       = 0x0012
	algSHA1Str   = "sha1"
	algSHA256Str = "sha256"
	algSHA384Str = "sha384"
	algSHA512Str = "sha512"
	algSM3Str    = "sm3"
	strfalse     = "false"
)

var (
	data_len1 int    = 3624
	uuid1     string = "test"
	taReport1        = []byte(
		`
{
        "report_sign":  {
                "sce_no_as":    "RIipRRfPKYILcAVDNr5F0Y13Y4tV2XH9MJD54VkAweVLeVLfUmkhAzVCN65yAts6pk51_nQiSZWcwMFePEMC5e93Mgkvls1f1pqnkDa6UcXUO-7Mm3gm1sDXr1lp5pClUQ_xGleOlHxRl7KiPwVCNm5dShgF2zrXk_F4dhrf06o4GU12HwTMhvs7m2CCp2VF76CBoJaveiZDUpZA6tHebtvqIWEUtqEyIuAVtOGee7bSoGJC54CtZmy_YzkB3W3RaWtPMus2vVdV1JZgEcdni_VVw1mBkicON9O2g1Vk2S8y75wql3q7-MgHyR13Pc9hgvXZYg8Lts3yo0CdvD9NPsKgA2LoB_rRHjd3PLe87mXYNhOErHnZotTTmD3GKOiU0fPnfyXCqGXOCS6by3hpiY9QclSP8inYUjGtxElTyzDJaXM-y1iExxvMdj1zQPkcSpk32ZAakDEH2fOEiCmU0cYTcdJTzEoBTw8hGoNb0FOFUMc-YVQCx9VzMjYF_-wD0xmyLzmVrWuwytQ6Dg8tIacILlt27bV8PZnLoyS0vOMIGjJ7A-NpmJSJRL5WGs7Hx-5WTVOR9Xg3p6z7jJypB61FMdkvpgltw89eYt7TVjyyrCovpJUg-zKg2YbET2_-GyjHoCLNutuVvGqPNEH9I4Kh9MZEKzZiiKKutJUhF_E"
        },
        "akcert":       {
                "sce_no_as":    {
                        "signature":    {
                                "drk_cert":     "TUlJRWtqQ0NBM3FnQXdJQkFnSVJFVk9HdExqeldMKzk2WEpGeWlYSVEwOHdEUVlKS29aSWh2Y05BUUVMQlFBd1BURUxNQWtHQTFVRUJoTUNRMDR4RHpBTkJnTlZCQW9UQmtoMVlYZGxhVEVkTUJzR0ExVUVBeE1VU0hWaGQyVnBJRWxVSUZCeWIyUjFZM1FnUTBFd0hoY05Nakl3TkRFeE1EWXpOVEF5V2hjTk16Y3dOREEzTURZek5UQXlXakE2TVFzd0NRWURWUVFHRXdKRFRqRVBNQTBHQTFVRUNoTUdTSFZoZDJWcE1Sb3dHQVlEVlFRREV4RXdNalpRVUZZeE1FdERNREEwTVRjNVZEQ0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQU5uOGJ6SXJneGFBNFh6RkZYSzhZYUhOVU5IZ2hoRzJZeEg4Znc4a0lTL1BaY3NkZXo2WTVLZ3BNVDJ0ZTRkVkpYa2FDeFVld1IxZm1Vb1AwZStsaWtYeVlaZm1xeDF6SVZoazRtM2tuK0lYN3g5c3RMeitvR0NaYXg2MXMrdURhNnBITGN4VDVKWUZZaFVHZ2FlbE1wS2lxamEvSFo2aHRCUW1oZ1YvNFFxTHl0ellKSlc2ZVFoRnMrQW9URUx5RmFBa0JXUlkzaVFRbE55NmhsV2xGa0xUQkdYSWYvZ0E2MmgyeE5wd3BPVkdjRi9mL2ZrdTBlR3JVZHVZUG04YVRlNnNITzZIOVdhY0xwU28wd1Nqc2hoME8xUzdrcWVJUTFLdWhDY0lkQnJKRWNyalA5RFUzQnJweGxzck5JKytHeTV0ays5Q3RZTzVsTktVbTJHUVpDUlZKaDFxUWNXb3hQWTZUYkNJZTZiMi9oaFJGdHVJM2VYcGczLzlmWW1NYllKb3ZTb1dxekErUzZCL092dmdCVjFhNzNod2kvQldiWjg5bWM3WG52S3I1MVBFeUIrTnMrRUpxczVXWTNnVy93VWlmajh3VWVSS2VqV3hnQzVwSkJVRzlPWWNyc2JZaExzdFAycHdvSHFaK2RFa1kxbytPY2hvWm5XYVl5ZHdYZDgwQWNiNWNkOU1RMUgyc1ZkMUxUb3BXMEt2SGhHUVE1OE1rTVFVSWdPRjVXam1pWExVc0NhcER3bHZrREdwc282UGFpN3VRTmZFOS95TjZRWlg4VXFscE5oNTAvVzcrK0ZrNUtKWWE3b1lDU2Q4Zk9tVElHTFpuUWRxNUFTWlZWM0d4Y2RxUDVGcmdwVVIzUUIvT3dUNzdWZjhMNlJBbjg0aU9Ec2ZQREJ6QWdNQkFBR2pnWTh3Z1l3d0h3WURWUjBqQkJnd0ZvQVVFb28zN1BselY5ZmtnN3ExYndQczNhNFJUczh3Q3dZRFZSMFBCQVFEQWdQNE1Gd0dDQ3NHQVFVRkJ3RUJCRkF3VGpBb0JnZ3JCZ0VGQlFjd0FvWWNhSFIwY0Rvdkx6RXlOeTR3TGpBdU1TOWpZV2x6YzNWbExtaDBiVEFpQmdnckJnRUZCUWN3QVlZV2FIUjBjRG92THpFeU55NHdMakF1TVRveU1EUTBNekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBSFc1OWZtTGNVMmQraWNuY2FHWGVoU3JlSEVjUThVbWRYWDE1a3E3eStnWTNJZklpTUgxSUNNVFZLL1hEbFZZR3ltMXFvUXdiV3hPSi9GOEFnOEFZVk1YcVpHZWtRRThCZGZNTk1tQmdnOWh6R3VoWEl2K2xzN3g5dVJBbEpEVlYyNWtOOWFNWC82RVBZNmk5cUgxTzlKdzdRRWd3T2JlTE5FM1VaY245bE90Q1BXZFhnWENROTlnNm1iSTA3Sng3Zlk0UStzVUpOQkxqNDVicy9JSUNjUGpBUS9HYjd6NEhScEtDREIzU3R6NmZaM0hjUlZiVy9BMmN3MUh3UDI3bXBuWXE4b290d216S1lydFpzbCs4YjhYQnFvME1zbWlYNmpHcTFJSi9hdjNDcUMxN0VGK2NwU3RrbXZacWFlZGdaVndPc1M2ZG83MXh4K0JnUFZlMnpnPT0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                                "drk_sign":     "j6YnW9t0RbxYkGt_KQoHdvHoeTHm40V6UWkaazcOY1igfi9XjBB_OGDHMx0uWJijhHGbpOx93sNgVc3yQJBLiQwxkLMeYIc6qaTZBaiiq9kxj-FGI952bbv65WF_JfPeCXvrgl0Hlhen1fhVV22PMmoK_MJ6vB9Pw5bsbTvCFpwlFA963X0_XWNLAzETp5rbjdkZd7dOmBmYFjm6DfrfO86xNeVrWYEomhpVYChEYkXSWkAeS7OCBSQHFJaw5HnKRtPGQDIe8C8cnPX8cI2RF-KVmBODxRz8mRQYosrrHMj8RqO0KG2JgPwmXZvLNahWDh_GyLBStHHNh7oDYmfX_DFEfqZlSrSUJCkmtQnO6-COW8KM85l1EYz9SFzwcdjh-qgG6p80NyfULDBTIUTNY6rFKTCGqD19BSd8HlOaaoSdw3nXlR4xSpMO3TxojLCkSOup8QtLO6bgUN5vJBEXuo6U33FcQXn-4-wL9SPuAOsa1PV7sSGk17nT31bT7LfqNzM4OO8eYnrPG98xM_Te6nkVJSfUc1e7mRelNUtZpwIxRRIhnDn37pAcqpCESiANxSko8-353ty8cm4VChUsRomR7AtFgRBuPqRrHx2J3eiRE5FsIiXBaMdEXbXHE70wexgEtw0RwhtgHv87iMgLo5H_D9KGWTByzNbjtC04W9g"
                        },
                        "payload":      {
                                "version":      "TEE.RA.1.0",
                                "timestamp":    "9223372036854770000",
                                "scenario":     "sce_no_as",
                                "sign_alg":     "PS256",
                                "hash_alg":     "HS256",
                                "qta_img":      "FaOPRQvji8yNYvo1K8XDMDXXK2lkwiegprur8djeKgc",
                                "qta_mem":      "KlYpkZzjREFXd0GwwgLas3gJ60HB0DQfsn8sHlZ7SjE",
                                "tcb":  "",
                                "ak_pub":       {
                                        "kty":  "RSA",
                                        "n":    "yf1gDkBMbaI7Z9t6A2WPBjRB3PfYaSPV0_hxu44bx53_Qt1pyvH4Y-S_34HJN5lIcdAxk-iuaTclK6VqZ919chgmlwf46peN0TCI0l4ijtgfpHn-naeeeVztyXBIc_xRJKLG24XPaszZoG9StlfpJOB8-WvAqw-c6wtc1I9BLkooGUYfJ-eddpD1-22DtfcgIKxOwp3eM0N5FQoN5bYAHIT68ZLE2ZsfhTuEfnm6uZDoETk-H21BiSICwReqmXyGrWC6-ISE4W5hz1vEZnz7u66a5CXt0Xaz6WiJ3dOYAa-a4rXDO4lGTttZ6wWu6QHANQC5HxrO0ySr8p5G2RK5tsrEG8yZMExo66bfJ9y2JhT4QQ8Xsh1CVGA6mZzxK4Ir56cjv8_ZHhYQNzOi4Y6KSm_4unR1p5USD_KFKQpXTrb_4fo3oJ8h_hWnGunc7FVUNuQGNbCqeuwsWfptyqQDH6CjqW1Z6mMR64rYaoOOxZohSdmmZH5xbW2h_5wkhkQK3Rv15oHuJX8j5Yz8NED6bXTOU1t28E4c1HAPRAEGNF3PxCWWiBiwWAfGHhbRvZIZ3pFVNHciag_E8e90tXQIP0aiYEn22esDTY4CpaMDEzsrkLd351QSEbW7uJACQBBH8PZvhNCLMIkGayh82NOu4cNjErG95BcElYHX0H40MoE",
                                        "e":    "AQAB"
                                }
                        },
                        "handler":      "provisioning-output"
                }
        },
        "payload":      {
                "version":      "TEE.RA.1.0",
                "timestamp":    "9223372036854775800",
                "nonce":        "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_gA",
                "scenario":     "sce_no_as",
                "uuid": "e08f7eca-e875-440e-9ab0-5f381136c600",
                "hash_alg":     "HS256",
                "sign_alg":     "PS256",
                "ta_mem":       "KlYpkZzjREFXd0GwwgLas3gJ60HB0DQfsn8sHlZ7SjE",
                "ta_img":       "FaOPRQvji8yNYvo1K8XDMDXXK2lkwiegprur8djeKgc",
                "ta_attr":      "",
                "tcb":  ""
        },
        "handler":      "report-output"
}
`)
)

type (
	tpm struct {
		config *TPMConfig
		useHW  bool
		dev    io.ReadWriteCloser
		ek     endorsementKey
		ik     attestationKey
	}

	// TPMConfig means tpm config information
	TPMConfig struct {
		IMALogPath    string
		BIOSLogPath   string
		ReportHashAlg string
		SeedPath      string
	}

	endorsementKey struct {
		pub      crypto.PublicKey
		handle   tpmutil.Handle
		alg      string
		password string
	}

	attestationKey struct {
		pub      crypto.PublicKey
		handle   tpmutil.Handle
		alg      string
		password string
		name     []byte
	}

	// IKCertInput means ik cert information,
	// and will be used to activate ik cert
	IKCertInput struct {
		// CredBlob & EncryptedSecret are created by MakeCredential, and will be given as input to ActivateCredential
		CredBlob        []byte // the protected key used to encrypt IK Cert
		EncryptedSecret []byte // the pretected secret related to protection of CredBlob
		// EncryptedCert is the encrypted IK Cert,
		// will be decypted with the key recovered from CredBlob & EncryptedSecret,
		// decrypted Cert will be in PEM format
		EncryptedCert []byte
		// if DecryptAlg == "AES128-CBC"
		// then it is the IV used to decrypt IK Cert together with the key recovered from CredBlob & EncryptedSecret
		DecryptAlg   string // the algorithm & scheme used to decrypt the IK Cert
		DecryptParam []byte // the parameter required by the decrypt algorithm to decrypt the IK Cert
	}
)

var (
	// ErrWrongParams means wrong input parameter error
	ErrWrongParams = errors.New("wrong input parameter")
	// ErrFailTPMInit means couldn't start tpm or init key/certificate
	ErrFailTPMInit = errors.New("couldn't start tpm or init key/certificate")
	// ErrReadPCRFail means failed to read all PCRs
	ErrReadPCRFail = errors.New("failed to read all PCRs")
	// ErrNotSupportedHashAlg means the set hash algorithm  is not supported
	ErrNotSupportedHashAlg = errors.New("the set hash algorithm  is not supported")

	algStrMap = map[tpm2.Algorithm]string{
		tpm2.AlgSHA1:   "SHA1",
		tpm2.AlgSHA256: "SHA256",
		tpm2.AlgSHA384: "SHA384",
		tpm2.AlgSHA512: "SHA512",
	}

	algIdMap = map[string]tpm2.Algorithm{
		algSHA1Str:   tpm2.AlgSHA1,
		algSHA256Str: tpm2.AlgSHA256,
		algSHA384Str: tpm2.AlgSHA384,
		algSHA512Str: tpm2.AlgSHA512,
		algSM3Str:    AlgSM3,
	}

	// PCR7 is for SecureBoot.
	pcrSelectionNil  = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{}}
	pcrSelection0    = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0}}
	pcrSelection0to7 = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7}}
	pcrSelection7    = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{7}}
	pcrSelectionAll  = tpm2.PCRSelection{Hash: tpm2.AlgSHA1,
		PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
			12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}}

	// according to TCG specification, B.3.3  Template L-1: RSA 2048 (Storage)
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r3.pdf
	// EKParams means ek parameters
	EKParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagDecrypt | tpm2.FlagRestricted,

		AuthPolicy: tpmutil.U16Bytes{0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 0,
			ModulusRaw: tpmutil.U16Bytes{ // 256 zeros
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	}

	// according to TCG specification, 7.3.4.2 Template H-1: RSA 2048
	// https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf
	// IKParams means ik parameters
	IKParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign | tpm2.FlagRestricted,

		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits:     2048,
			ExponentRaw: 0,
		},
	}

	tpmRef *tpm = nil
)

// GetEKPub returns EK public key
func GetEKPub() crypto.PublicKey {
	if tpmRef == nil {
		return nil
	}
	return tpmRef.ek.pub
}

// GetIKPub returns IK public key
func GetIKPub() crypto.PublicKey {
	if tpmRef == nil {
		return nil
	}
	return tpmRef.ik.pub
}

// GetIKName returns IK name
func GetIKName() []byte {
	if tpmRef == nil {
		return nil
	}
	return tpmRef.ik.name
}

// SetDigestAlg method update the Digest alg used to get pcrs and to do the quote.
func SetDigestAlg(alg string) error {
	if tpmRef == nil {
		return ErrFailTPMInit
	}

	if algID, ok := algIdMap[alg]; ok {
		pcrSelection0.Hash = algID
		pcrSelection0to7.Hash = algID
		pcrSelection7.Hash = algID
		pcrSelectionAll.Hash = algID
		tpmRef.config.ReportHashAlg = alg
		return nil
	}
	return ErrNotSupportedHashAlg

}

// OpenTPM uses either a physical TPM device(default/useHW=true) or a
// simulator(-t/useHW=false), returns a global TPM object variable.
func OpenTPM(useHW bool, conf *TPMConfig, seed int64) error {
	if tpmRef != nil {
		return nil
	}
	if conf == nil {
		return ErrWrongParams
	}
	tpmRef = &tpm{
		config: conf,
		useHW:  useHW,
		dev:    nil,
	}
	SetDigestAlg(conf.ReportHashAlg)
	var err error
	if useHW {
		err = openTpmChip()
	} else {
		err = openTpmSimulator(seed)
	}
	return err
}

// openTpmChip opens TPM hardware chip and reads EC from NVRAM.
// NOTICE:
//
// # User should use tbprovisioner command tool to write the EC
//
// into TPM NVRAM before running raagent or the TPM chip already
// has EC in NVRAM when it comes from manufactories.
func openTpmChip() error {
	var err error
	tpmRef.dev, err = tpm2.OpenTPM(tpmDevPath1)
	if err != nil {
		tpmRef.dev, err = tpm2.OpenTPM(tpmDevPath2)
	}
	return err
}

// openTpmSimulator opens TPM simulator.
// EK/IK key and certificate should be loaded/generated from files by config.
func openTpmSimulator(seed int64) error {
	// GetWithFixedSeedInsecure behaves like Get() expect that all of the
	// internal hierarchy seeds are derived from the input seed. So every
	// time we reopen the simulator, we can always get the same ek for the
	// same input.
	var err error
	tpmRef.dev, err = simulator.GetWithFixedSeedInsecure(seed)
	return err
}

// CloseTPM closes an open tpm device and flushes tpm resources.
func CloseTPM() {
	if tpmRef == nil {
		return
	}
	if tpmRef.ek.handle != tpmutil.Handle(0) {
		tpm2.FlushContext(tpmRef.dev, tpmRef.ek.handle)
	}
	if tpmRef.ik.handle != tpmutil.Handle(0) {
		tpm2.FlushContext(tpmRef.dev, tpmRef.ik.handle)
	}
	tpmRef.dev.Close()
	tpmRef = nil
}

// DefineNVRAM defines the index space as size length in the NVRAM
func DefineNVRAM(idx uint32, size uint16) error {
	if tpmRef == nil {
		return ErrFailTPMInit
	}
	attr := tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead |
		tpm2.AttrWriteSTClear | tpm2.AttrReadSTClear
	return tpm2.NVDefineSpace(tpmRef.dev, tpm2.HandleOwner, tpmutil.Handle(idx),
		emptyPassword, emptyPassword, nil, attr, size)
}

// UndefineNVRAM frees the index space in the NVRAM
func UndefineNVRAM(idx uint32) error {
	if tpmRef == nil {
		return ErrFailTPMInit
	}
	return tpm2.NVUndefineSpace(tpmRef.dev, emptyPassword, tpm2.HandleOwner,
		tpmutil.Handle(idx))
}

// WriteNVRAM writes the data at index into the NVRAM
func WriteNVRAM(idx uint32, data []byte) error {
	if tpmRef == nil {
		return ErrFailTPMInit
	}
	l := uint16(len(data))
	offset := uint16(0)
	end := uint16(0)
	for l > 0 {
		if l < blockSize {
			end = offset + l
			l = 0
		} else {
			end = offset + blockSize
			l -= blockSize
		}
		err := tpm2.NVWrite(tpmRef.dev, tpm2.HandleOwner, tpmutil.Handle(idx),
			emptyPassword, data[offset:end], offset)
		if err != nil {
			return err
		}
		offset = end
	}
	return nil
}

// ReadNVRAM reads the data at index from the NVRAM
func ReadNVRAM(idx uint32) ([]byte, error) {
	if tpmRef == nil {
		return nil, ErrFailTPMInit
	}
	return tpm2.NVReadEx(tpmRef.dev, tpmutil.Handle(idx),
		tpm2.HandleOwner, emptyPassword, 0)
}

// GenerateEKey generates the ek key by tpm2, gets the handle and public part
func GenerateEKey() error {
	var err error
	if tpmRef == nil {
		return ErrFailTPMInit
	}
	// for TPM chip, maybe need to load EKParams from NVRAM to create the
	// same EK as the saved EC in NVRAM, need to test!!!
	tpmRef.ek.handle, tpmRef.ek.pub, err = tpm2.CreatePrimary(tpmRef.dev,
		tpm2.HandleEndorsement, pcrSelectionNil,
		emptyPassword, emptyPassword, EKParams)
	if err != nil {
		tpmRef.ek.handle = tpmutil.Handle(0)
		tpmRef.ek.pub = nil
		return err
	}
	return nil
}

// GenerateIKey generates the ik key as a primary key by tpm2, gets the handle, public
// and name fields to use later
func GenerateIKey() error {
	var err error
	if tpmRef == nil {
		return ErrFailTPMInit
	}
	tpmRef.ik.handle, tpmRef.ik.pub, err = tpm2.CreatePrimary(tpmRef.dev,
		tpm2.HandleEndorsement, pcrSelectionNil,
		emptyPassword, emptyPassword, IKParams)
	if err != nil {
		tpmRef.ik.handle = tpmutil.Handle(0)
		tpmRef.ik.pub = nil
		return err
	}
	_, ikName, _, err := tpm2.ReadPublic(tpmRef.dev, tpmRef.ik.handle)
	if err != nil {
		return err
	}
	tpmRef.ik.password = emptyPassword
	tpmRef.ik.name = ikName
	return nil
}

// ActivateIKCert decrypts the IkCert from the input, and return it in PEM format
func ActivateIKCert(in *IKCertInput) ([]byte, error) {
	if tpmRef == nil {
		return nil, ErrFailTPMInit
	}
	sessHandle, _, err := tpm2.StartAuthSession(tpmRef.dev, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16),
		nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return nil, errors.New("StartAuthSession() failed, error:" + err.Error())
	}
	defer tpm2.FlushContext(tpmRef.dev, sessHandle)

	if _, err = tpm2.PolicySecret(tpmRef.dev, tpm2.HandleEndorsement,
		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
		sessHandle, nil, nil, nil, 0); err != nil {
		return nil, errors.New("PolicySecret() failed, error:" + err.Error())
	}

	recoveredCredential, err := tpm2.ActivateCredentialUsingAuth(tpmRef.dev, []tpm2.AuthCommand{
		{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(emptyPassword)},
		{Session: sessHandle, Attributes: tpm2.AttrContinueSession, Auth: []byte(emptyPassword)},
	}, tpmRef.ik.handle, tpmRef.ek.handle, in.CredBlob, in.EncryptedSecret)
	if err != nil {
		return nil, errors.New("ActivateCredentialWithAuth error:" + err.Error())
	}
	var alg, mode uint16
	switch in.DecryptAlg {
	case cryptotools.Encrypt_Alg: // AES128_CBC
		alg, mode = cryptotools.AlgAES, cryptotools.AlgCBC
	default:
		return nil, err
	}
	IKCert, err := cryptotools.SymmetricDecrypt(alg, mode,
		recoveredCredential, in.DecryptParam, in.EncryptedCert)
	if err != nil {
		return nil, err
	}
	return IKCert, nil
}

// GetClientInfo returns json format client information.
func GetClientInfo() (string, error) {
	var err error
	var out0 bytes.Buffer
	var out1 bytes.Buffer
	var out2 bytes.Buffer
	if tpmRef == nil {
		return "", ErrFailTPMInit
	}
	if tpmRef.useHW {
		// execute dmidecode shell-commands to acquire information
		// remind: need sudo permission
		cmd0 := exec.Command("dmidecode", "-t", "0")
		cmd0.Stdout = &out0
		if err = cmd0.Run(); err != nil {
			return "", err
		}
		cmd1 := exec.Command("dmidecode", "-t", "1")
		cmd1.Stdout = &out1
		if err = cmd1.Run(); err != nil {
			return "", err
		}
	} else {
		out0.WriteString(constDMIBIOS)
		out1.WriteString(constDMISYSTEM)
	}
	cmd2 := exec.Command("uname", "-a")
	cmd2.Stdout = &out2
	if err = cmd2.Run(); err != nil {
		return "", err
	}
	clientInfo := map[string]string{}
	start0 := strings.Index(out0.String(), "BIOS Information")
	start1 := strings.Index(out1.String(), "System Information")
	clientInfo["bios"] = out0.String()[start0:]
	clientInfo["system"] = out1.String()[start1:]
	clientInfo["os"] = out2.String()
	clientInfo["ip"] = typdefs.GetIP()
	clientInfo["version"] = "2.0.2"
	strCI, err := json.Marshal(clientInfo)
	return string(strCI), err
}

func readPcrLog(pcrSelection tpm2.PCRSelection) ([]byte, error) {
	var buf bytes.Buffer
	var digBuf []byte
	switch pcrSelection.Hash {
	case tpm2.AlgSHA1:
		digBuf = make([]byte, typdefs.Sha1DigestLen*2)
	case tpm2.AlgSHA256:
		digBuf = make([]byte, typdefs.Sha256DigestLen*2)
	case AlgSM3:
		digBuf = make([]byte, typdefs.SM3DigestLen*2)
	}
	numPCRs := len(pcrSelection.PCRs)
	// read pcr one by one by ordering
	for i := 0; i < numPCRs; i++ {
		pcrSel := tpm2.PCRSelection{
			Hash: pcrSelection.Hash,
			PCRs: []int{i},
		}
		// Ask the TPM for those PCR values.
		ret, err := tpm2.ReadPCRs(tpmRef.dev, pcrSel)
		if err != nil {
			return nil, err
		}
		// Keep track of the PCRs we were actually given.
		for pcr, digest := range ret {
			hex.Encode(digBuf, digest)
			buf.Write(digBuf)
			switch pcrSelection.Hash {
			case tpm2.AlgSHA1:
				buf.WriteString(fmt.Sprintf(" sha1 %02d\n", pcr))
			case tpm2.AlgSHA256:
				buf.WriteString(fmt.Sprintf(" sha256 %02d\n", pcr))
			case AlgSM3:
				buf.WriteString(fmt.Sprintf(" sm3 %02d\n", pcr))
			}
		}
	}
	return buf.Bytes(), nil
}

// GetTrustReport takes a nonce input, generates the current trust report
func GetTrustReport(
	clientID int64,
	nonce uint64,
	algStr string,
	taTestMode bool,
	qcaserver string) (*typdefs.TrustReport, error) {
	if tpmRef == nil {
		return nil, ErrFailTPMInit
	}
	clientInfo, err := GetClientInfo()
	if err != nil {
		return nil, err
	}
	tRepIn := typdefs.TrustReportInput{
		ClientID:   clientID,
		Nonce:      nonce,
		ClientInfo: clientInfo,
	}
	// we use TrustReportIn as user data of Quote to guarantee its integrity
	repHash, err := tRepIn.Hash(algStr)
	if err != nil {
		return nil, err
	}
	quoted, signature, err := tpm2.Quote(tpmRef.dev,
		tpmRef.ik.handle, tpmRef.ik.password, emptyPassword,
		repHash, pcrSelectionAll, tpm2.AlgNull)
	if err != nil {
		return nil, err
	}
	jsonSignature, err := json.Marshal(signature)
	if err != nil {
		return nil, err
	}
	pcrLog, err := readPcrLog(pcrSelectionAll)
	if err != nil {
		return nil, err
	}
	biosLog, err := ioutil.ReadFile(tpmRef.config.BIOSLogPath)
	if err != nil {
		return nil, err
	}
	imaLog, err := ioutil.ReadFile(tpmRef.config.IMALogPath)
	if err != nil {
		return nil, err
	}
	report := typdefs.TrustReport{
		ClientID:   tRepIn.ClientID,
		Nonce:      tRepIn.Nonce,
		ClientInfo: tRepIn.ClientInfo,
		Quoted:     quoted,
		Signature:  jsonSignature,
		Manifests: []typdefs.Manifest{
			{Key: typdefs.StrPcr, Value: pcrLog},
			{Key: typdefs.StrBios, Value: biosLog},
			{Key: typdefs.StrIma, Value: imaLog},
		},
	}

	taReports, err := buildTaReport(nonce, qcaserver, taTestMode)
	if err != nil {
		return nil, err
	}
	report.TaReports = taReports

	return &report, nil
}

func buildTaReport(nonce uint64, qcaserver string, taTestMode bool) (map[string][]byte, error) {
	taReports := map[string][]byte{}
	if !taTestMode {
		talist, err := ioutil.ReadFile(talistpath)
		if err != nil {
			return nil, err
		}
		lines := bytes.Split(talist, typdefs.NewLine)
		for _, ln := range lines {
			// words[0]是uuid words[1]是with_tcb
			words := bytes.Split(ln, typdefs.Space)
			with_tcb := true
			if len(words) != 4 {
				continue
			}
			if string(words[1]) == strfalse {
				with_tcb = false
			}
			// convert hex to decimal
			tauuid, err := convertHex2Decimal(words[0])
			if err != nil {
				return nil, err
			}
			bytesBuffer := bytes.NewBuffer([]byte{})
			binary.Write(bytesBuffer, binary.LittleEndian, nonce)
			taReport, err := getTaReport(tauuid, bytesBuffer.Bytes(), with_tcb, qcaserver)
			if err != nil {
				return nil, err
			}
			taReports[string(words[0])] = taReport
		}
	} else {
		taReports[uuid1] = taReport1
	}
	return taReports, nil
}

// convert hex to Uuid
func convertHex2Decimal(hexuuid []byte) ([]byte, error) {
	strHorizontalBars := []byte("-")
	pure_hexuuid := bytes.Split(hexuuid, strHorizontalBars)
	var buffer bytes.Buffer
	for _, pure_hex := range pure_hexuuid {
		buffer.Write(pure_hex)
	}
	connect_pure_hexuuid := buffer.Bytes()
	var buffer2 bytes.Buffer
	for i := 0; i < len(connect_pure_hexuuid); i += 2 {
		hex_val := string(connect_pure_hexuuid[i]) + string(connect_pure_hexuuid[i+1])
		n, err := strconv.ParseUint(hex_val, 16, 32)
		if err != nil {
			return nil, err
		}
		n2 := uint8(n)
		buffer2.Write([]byte{n2})
	}
	final_uuid := buffer2.Bytes()
	return final_uuid, nil
}

// remote invoke qca api to get the TA's info
func getTaReport(uuid []byte, nonce []byte, with_tcb bool, server string) ([]byte, error) {
	reqID := qapi.GetReportRequest{
		Uuid:    uuid,
		Nonce:   nonce,
		WithTcb: with_tcb,
	}

	rpyID, err := qapi.DoGetTeeReport(server, &reqID)
	if err != nil {
		log.Printf("Get TA infomation failed, uuid: %v error: %v", uuid, err)
		return nil, err
	}
	log.Print("Get TA report succeeded!")

	return rpyID.GetTeeReport(), nil
}

func getManifest(imaPath, biosPath string) ([]typdefs.Manifest, error) {
	var manifest []typdefs.Manifest
	f, err := ioutil.ReadFile(imaPath)
	if err == nil {
		manifest = append(manifest, typdefs.Manifest{Key: "ima", Value: f})
	}

	f, err = ioutil.ReadFile(biosPath)
	if err == nil {
		manifest = append(manifest, typdefs.Manifest{Key: "bios", Value: f})
	}

	return manifest, err
}

// PreparePCRsTest method replay the bios/ima manifests into pcrs in test mode.
func PreparePCRsTest() error {
	if tpmRef.useHW {
		return nil
	}
	pcrs := typdefs.NewPcrGroups()
	// read the manifest files into memory
	manifest, err := getManifest(tpmRef.config.IMALogPath, tpmRef.config.BIOSLogPath)
	if err != nil {
		return err
	}

	// replay bios manifest
	biosContent := getManifestContent(manifest, typdefs.StrBios)
	if biosContent != nil {
		replayBIOSManifestTest(pcrs, biosContent)
	}
	// replay ima manifest
	imaContent := getManifestContent(manifest, typdefs.StrIma)
	if imaContent != nil {
		replayIMAManifestTest(pcrs, imaContent)
	}

	return nil
}

func getManifestContent(ms []typdefs.Manifest, t string) []byte {
	for _, m := range ms {
		if m.Key == t {
			return m.Value
		}
	}
	return nil
}

func replayBIOSManifestTest(pcrs *typdefs.PcrGroups, content []byte) error {
	// use bios manifest to replay pcrs
	btLog, _ := typdefs.TransformBIOSBinLogToTxt(content)
	typdefs.ExtendPCRWithBIOSTxtLog(pcrs, btLog)
	algID := algIdMap[tpmRef.config.ReportHashAlg]
	var v [24][]byte
	switch tpmRef.config.ReportHashAlg {
	case typdefs.Sha1AlgStr:
		v = pcrs.Sha1Pcrs
	case typdefs.Sha256AlgStr:
		v = pcrs.Sha256Pcrs
	case typdefs.Sm3AlgStr:
		v = pcrs.SM3Pcrs
	}
	for i := 0; i < typdefs.PcrMaxNum; i++ {
		tpm2.PCRExtend(tpmRef.dev, tpmutil.Handle(i), algID, v[i], emptyPassword)
	}

	return nil
}

func replayIMAManifestTest(pcrs *typdefs.PcrGroups, content []byte) error {
	// use ima manifest to replay pcrs
	typdefs.ExtendPCRWithIMALog(pcrs, content, tpmRef.config.ReportHashAlg)
	algID := algIdMap[tpmRef.config.ReportHashAlg]
	var v [24][]byte
	switch tpmRef.config.ReportHashAlg {
	case typdefs.Sha1AlgStr:
		v = pcrs.Sha1Pcrs
	case typdefs.Sha256AlgStr:
		v = pcrs.Sha256Pcrs
	case typdefs.Sm3AlgStr:
		v = pcrs.SM3Pcrs
	}
	for i := 0; i < typdefs.PcrMaxNum; i++ {
		tpm2.PCRExtend(tpmRef.dev, tpmutil.Handle(i), algID, v[i], emptyPassword)
	}

	return nil
}
