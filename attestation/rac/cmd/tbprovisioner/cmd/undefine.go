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
Create: 2021-12-06
Description: Command line tool for tpm provision process.
*/

package cmd

import (
	"fmt"
	"os"
	"strings"

	"gitee.com/openeuler/kunpengsecl/attestation/rac/ractools"
	"github.com/spf13/cobra"
)

var (
	// undefineCmd represents the undefine command
	undefineCmd = &cobra.Command{
		Use:   "undefine [nvram]",
		Short: "undefine TPM NVRAM content",
		Long: `Use this command to undefine TPM NVRAM content at index.
		` + ConstExample,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
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
			tpmConf := ractools.TPMConfig{}
			if uSim {
				tpmConf.IMALogPath = ractools.TestImaLogPath
				tpmConf.BIOSLogPath = ractools.TestBiosLogPath
				tpmConf.ReportHashAlg = ""
			} else {
				tpmConf.IMALogPath = ractools.ImaLogPath
				tpmConf.BIOSLogPath = ractools.BiosLogPath
				tpmConf.ReportHashAlg = ""
			}
			err := ractools.OpenTPM(!uSim, &tpmConf, 0)
			if err != nil {
				fmt.Printf(errOpenTPM, err)
				os.Exit(1)
			}
			defer ractools.CloseTPM()
			if uIndex == 0 {
				uIndex = ractools.IndexRsa2048EKCert
			}
			ractools.UndefineNVRAM(uIndex)
		},
	}
	uIndex uint32
	uSim   bool
)

func init() {
	rootCmd.AddCommand(undefineCmd)

	undefineCmd.Flags().Uint32VarP(&uIndex, LongIndex, ShortIndex, 0, constUIndexHelp)
	undefineCmd.Flags().BoolVarP(&uSim, LongSimulator, ShortSimulator, false, ConstSimulator)
}
