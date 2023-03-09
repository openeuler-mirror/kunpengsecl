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
Create: 2021-12-02
Description: Command line tool for tpm provision process.
*/

package cmd

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"gitee.com/openeuler/kunpengsecl/attestation/rac/ractools"
	"github.com/spf13/cobra"
)

const (
	// for command flags const long and strings.
	// LongIndex means the full name of index
	LongIndex = "index"
	// ShortIndex means the shorthand of index
	ShortIndex = "i"
	// LongFile means the full name of file
	LongFile = "file"
	// ShortFile means the shorthand of file
	ShortFile = "f"
	// ConstFile means PEM format file
	ConstFile = "the file to read content from, PEM format"
	// LongType means the full name of type
	LongType = "type"
	// ShortType means the shorthand of type
	ShortType = "t"
	// ConstType is used to prompt DER, PEM and STR information
	ConstType = `the output type DER/PEM (DEFAULT: DER)
    DER: the data needs to be transfered from PEM to DER
    PEM: the data is PEM and can directly write into NVRAM
    STR: the data is readable string for testing`
	// LongLength means length
	LongLength = "len"
	// ShortLength means the shorthand of length
	ShortLength = "l"
	// LongSimulator means the full name of simulator
	LongSimulator = "simulator"
	// ShortSimulator means the shorthand of simulator
	ShortSimulator = "s"
	// ConstSimulator is used to prompt simulator information
	ConstSimulator = "use the simulator to test (DEFAULT: false)"
	// ConstExample is used to show an example
	ConstExample = `
For example:
    # define a 128 bytes space for storage at 0x1000001 in NVRAM.
    tbprovisioner define nvram -i 0x1000001 -l 128

    # write data from command
    tbprovisioner write nvram "Hello world! I'm here!" -i 0x1000001 -t STR
    # or write data from file
    echo "Another test from file!" > data.txt
    tbprovisioner write nvram -i 0x1000001 -f data.txt -t STR

    # read data from NVRAM at index 0x1000001
    tbprovisioner read nvram -i 0x1000001 -t STR

    # undefine this index space
    tbprovisioner undefine nvram -i 0x1000001
`
	// for input parameter const strings.
	// ConstNVRAM means the string NVRAM const
	ConstNVRAM = "NVRAM"
	// ConstPCR means the string PCR const
	ConstPCR = "PCR"
	// ConstPEM means the string PEM const
	ConstPEM = "PEM"
	// ConstDER means the string DER const
	ConstDER = "DER"
	// ConstSTR means the string STR const
	ConstSTR = "STR"
	// for error messages.
	errOpenTPM    = "can't open TPM, %v\n"
	errReadNVRAM  = "read NVRAM(0x%08X) error: %v\n"
	errReadPCR    = "read PCR(%d) error: %v\n"
	errReadFile   = "read file(%s) error: %v\n"
	errWriteNVRAM = "write NVRAM(0x%08X) error: %v\n"
	errWriteFile  = "write file(%s) error: %v\n"
	// long help string
	constIndexList = `
    0x01C00002   RSA 2048 EK Certificate
    0x01C00003   RSA 2048 EK Nonce
    0x01C00004   RSA 2048 EK Template
    0x01C0000A   ECC NIST P256 EK Certificate
    0x01C0000B   ECC NIST P256 EK Nonce
    0x01C0000C   ECC NIST P256 EK Template
    0x01C00012   RSA 2048 EK Certificate (H-1)
    0x01C00014   ECC NIST P256 EK Certificate (H-2)
    0x01C00016   ECC NIST P384 EK Certificate (H-3)
    0x01C00018   ECC NIST P512 EK Certificate (H-4)
    0x01C0001A   ECC SM2_P256 EK Certificate (H-5)
    0x01C0001C   RSA 3072 EK Certificate (H-6)
    0x01C0001E   RSA 4096 EK Certificate (H-7)`
	constDIndexHelp = `the NVRAM index to define (DEFAULT: 0x01C00002)` + constIndexList
	constUIndexHelp = `the NVRAM index to undefine (DEFAULT: 0x01C00002)` + constIndexList
	constRIndexHelp = `the NVRAM index to read from (DEFAULT: 0x01C00002)` + constIndexList
	constWIndexHelp = `the NVRAM index to write to (DEFAULT: 0x01C00002)` + constIndexList
)

var (
	// readCmd represents the read command
	readCmd = &cobra.Command{
		Use:   "read [nvram|pcr]",
		Short: "Read TPM NVRAM|PCR content",
		Long: `Use this command to read TPM resources(nvram, pcr, etc) and save to
file(Default: StdOut) with the define format(Default: PEM).
` + ConstExample,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Println(cmd.Long)
				fmt.Println(cmd.UsageString())
				os.Exit(1)
			}
			obj := strings.ToUpper(args[0])
			if obj != ConstNVRAM && obj != ConstPCR {
				fmt.Println(cmd.Long)
				fmt.Println(cmd.UsageString())
				os.Exit(1)
			}
			tpmConf := ractools.TPMConfig{}
			if rSim {
				tpmConf.IMALogPath = ractools.TestImaLogPath
				tpmConf.BIOSLogPath = ractools.TestBiosLogPath
				tpmConf.ReportHashAlg = ""
			} else {
				tpmConf.IMALogPath = ractools.ImaLogPath
				tpmConf.BIOSLogPath = ractools.BiosLogPath
				tpmConf.ReportHashAlg = ""
			}
			err := ractools.OpenTPM(!rSim, &tpmConf, 0)
			if err != nil {
				fmt.Printf(errOpenTPM, err)
				os.Exit(1)
			}
			defer ractools.CloseTPM()
			switch obj {
			case ConstNVRAM:
				nvramHandle()
			case ConstPCR:
				pcrHandle()
			}
		},
	}
	rIndex uint32
	rFile  string
	rType  string
	rSim   bool
)

func init() {
	rootCmd.AddCommand(readCmd)

	readCmd.Flags().Uint32VarP(&rIndex, LongIndex, ShortIndex, 0, constRIndexHelp)
	readCmd.Flags().StringVarP(&rFile, LongFile, ShortFile, "", "the file to write content into")
	readCmd.Flags().StringVarP(&rType, LongType, ShortType, "", "the output type PEM/DER/STR (DEFAULT: PEM)")
	readCmd.Flags().BoolVarP(&rSim, LongSimulator, ShortSimulator, false, ConstSimulator)
}

func nvramHandle() {
	if rIndex == 0 {
		rIndex = ractools.IndexRsa2048EKCert
	}
	buf, err := ractools.ReadNVRAM(rIndex)
	if err != nil {
		fmt.Printf(errReadNVRAM, rIndex, err)
		os.Exit(1)
	}
	var out []byte
	rType = strings.ToUpper(rType)
	if rType == ConstDER || rType == ConstSTR {
		out = buf
	} else {
		block := &pem.Block{Bytes: buf}
		out = pem.EncodeToMemory(block)
	}
	if rFile == "" {
		if rType == ConstDER {
			fmt.Printf("%v", out)
		} else {
			fmt.Printf("%s", out)
		}
	} else {
		err = ioutil.WriteFile(rFile, out, 0644)
		if err != nil {
			fmt.Printf(errWriteFile, rFile, err)
		}
	}
}

func pcrHandle() {
	//fmt.Printf(errReadPCR, rIndex, err)
	//fmt.Printf(constWritePCR, rIndex, buf)
}
