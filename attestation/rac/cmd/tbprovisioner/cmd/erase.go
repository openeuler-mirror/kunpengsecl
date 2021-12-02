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
Create: 2021-12-02
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
	// eraseCmd represents the erase command
	eraseCmd = &cobra.Command{
		Use:   "erase [nvram]",
		Short: "Erase TPM NVRAM content",
		Long:  `Use this command to erase TPM NVRAM content at defined index.`,
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
			tp, err := ractools.OpenTPM(!eSim)
			if err != nil {
				fmt.Printf(errOpenTPM, err)
				os.Exit(1)
			}
			defer tp.Close()
			if eIndex == 0 {
				eIndex = ractools.IndexRsa2048EKCert
			}
			tp.EraseEKCert(eIndex)
		},
	}
	eIndex uint32
	eSim   bool
)

func init() {
	rootCmd.AddCommand(eraseCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// eraseCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// eraseCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	eraseCmd.Flags().Uint32VarP(&eIndex, LongIndex, ShortIndex, 0, constEIndexHelp)
	eraseCmd.Flags().BoolVarP(&eSim, LongSimulator, ShortSimulator, false, "use the simulator to test (DEFAULT: false)")
}
