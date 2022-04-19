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

var (
	// writeCmd represents the write command
	writeCmd = &cobra.Command{
		Use:   "write [nvram] [data]",
		Short: "Write TPM NVRAM content",
		Long: `Use this command to write data to TPM nvram with DER/PEM/STR format.
The data comes from input or from a file. Default input data is PEM format.
` + ConstExample,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 || len(args) > 2 {
				fmt.Println(cmd.Long)
				fmt.Println(cmd.UsageString())
				os.Exit(1)
			}
			obj := strings.ToUpper(args[0])
			if obj != ConstNVRAM {
				fmt.Println(cmd.Long)
				fmt.Println(cmd.UsageString())
				os.Exit(1)
			}
			var buf []byte
			var err error
			if len(args) == 2 {
				buf = []byte(args[1])
			} else {
				buf, err = ioutil.ReadFile(wFile)
				if err != nil {
					fmt.Printf(errReadFile, wFile, err)
					os.Exit(1)
				}
			}
			tpmConf := ractools.TPMConfig{}
			if wSim {
				tpmConf.IMALogPath = ractools.TestImaLogPath
				tpmConf.BIOSLogPath = ractools.TestBiosLogPath
				tpmConf.ReportHashAlg = ""
			} else {
				tpmConf.IMALogPath = ractools.ImaLogPath
				tpmConf.BIOSLogPath = ractools.BiosLogPath
				tpmConf.ReportHashAlg = ""
			}
			err = ractools.OpenTPM(!wSim, &tpmConf)
			if err != nil {
				fmt.Printf(errOpenTPM, err)
				os.Exit(1)
			}
			defer ractools.CloseTPM()
			if wIndex == 0 {
				wIndex = ractools.IndexRsa2048EKCert
			}
			wType = strings.ToUpper(wType)
			if wType == ConstDER {
				block, _ := pem.Decode(buf)
				if block != nil {
					err = ractools.WriteNVRAM(wIndex, block.Bytes)
				}
			} else {
				err = ractools.WriteNVRAM(wIndex, buf)
			}
			if err != nil {
				fmt.Printf(errWriteNVRAM, wIndex, err)
				os.Exit(1)
			}
		},
	}
	wIndex uint32
	wFile  string
	wType  string
	wSim   bool
)

func init() {
	rootCmd.AddCommand(writeCmd)

	writeCmd.Flags().Uint32VarP(&wIndex, LongIndex, ShortIndex, 0, constWIndexHelp)
	writeCmd.Flags().StringVarP(&wFile, LongFile, ShortFile, "", ConstFile)
	writeCmd.Flags().StringVarP(&wType, LongType, ShortType, "", ConstType)
	writeCmd.Flags().BoolVarP(&wSim, LongSimulator, ShortSimulator, false, ConstSimulator)
}
