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
		Use:   "write [nvram]",
		Short: "Write TPM NVRAM content",
		Long: `Use this command to read content from file (PEM format) and write to
TPM resources(nvram, etc) with the define format(Default: DER).
`,
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
			tp, err := ractools.OpenTPM(!wSim)
			if err != nil {
				fmt.Printf(errOpenTPM, err)
				os.Exit(1)
			}
			defer tp.Close()
			buf, err := ioutil.ReadFile(wFile)
			if err != nil {
				fmt.Printf(errReadFile, wFile, err)
				os.Exit(1)
			}
			if wIndex == 0 {
				wIndex = ractools.IndexRsa2048EKCert
			}
			wType = strings.ToUpper(wType)
			if wType == "" || wType == ConstDER {
				block, _ := pem.Decode(buf)
				err = tp.WriteEKCert(wIndex, block.Bytes)
			} else if wType == ConstPEM {
				err = tp.WriteEKCert(wIndex, buf)
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

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// writeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// writeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	writeCmd.Flags().Uint32VarP(&wIndex, LongIndex, ShortIndex, 0, constWIndexHelp)
	writeCmd.Flags().StringVarP(&wFile, LongFile, ShortFile, "", "the file to read content from")
	writeCmd.Flags().StringVarP(&wType, LongType, ShortType, "", "the output type DER/PEM (DEFAULT: DER)")
	writeCmd.Flags().BoolVarP(&wSim, LongSimulator, ShortSimulator, false, "use the simulator to test (DEFAULT: false)")
}
