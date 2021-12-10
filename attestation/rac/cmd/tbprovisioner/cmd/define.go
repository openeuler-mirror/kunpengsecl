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

// defineCmd represents the define command
var (
	defineCmd = &cobra.Command{
		Use:   "define [nvram]",
		Short: "define TPM NVRAM content",
		Long: `Use this command to define TPM NVRAM content at index.
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
			if dLength > 2048 {
				fmt.Println("data length is too long.")
				os.Exit(1)
			}
			tpmConf := ractools.TPMConfig{}
			if dSim {
				tpmConf.IMALogPath = ractools.TestImaLogPath
				tpmConf.BIOSLogPath = ractools.TestBiosLogPath
				tpmConf.ReportHashAlg = ""
			} else {
				tpmConf.IMALogPath = ractools.ImaLogPath
				tpmConf.BIOSLogPath = ractools.BiosLogPath
				tpmConf.ReportHashAlg = ""
			}
			tp, err := ractools.OpenTPM(!dSim, &tpmConf)
			if err != nil {
				fmt.Printf(errOpenTPM, err)
				os.Exit(1)
			}
			defer tp.Close()
			if dIndex == 0 {
				dIndex = ractools.IndexRsa2048EKCert
			}
			tp.DefineNVRAM(dIndex, uint16(dLength))
		},
	}
	dIndex  uint32
	dLength uint32
	dSim    bool
)

func init() {
	rootCmd.AddCommand(defineCmd)

	defineCmd.Flags().Uint32VarP(&dIndex, LongIndex, ShortIndex, 0, constDIndexHelp)
	defineCmd.Flags().Uint32VarP(&dLength, LongLength, ShortLength, 0, "define the saved data length")
	defineCmd.Flags().BoolVarP(&dSim, LongSimulator, ShortSimulator, false, ConstSimulator)
}
