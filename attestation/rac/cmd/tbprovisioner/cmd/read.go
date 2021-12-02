/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"gitee.com/openeuler/kunpengsecl/attestation/rac/ractools"
	"github.com/spf13/cobra"
)

const (
	constNVRAM      = "NVRAM"
	constPCR        = "PCR"
	constPEM        = "PEM"
	constDER        = "DER"
	errReadNVRAM    = "read NVRAM(0x%08X) error: %v\n"
	errReadPCR      = "read PCR(%d) error: %v\n"
	constWriteNVRAM = "NVRAM(0x%08X): %v\n"
	constWritePCR   = "PCR(%d): %v\n"
	constIndexHelp  = `the NVRAM index to read from (DEFAULT: 0x01C00002)
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
)

var (
	// readCmd represents the read command
	readCmd = &cobra.Command{
		Use:   "read [nvram|pcr]",
		Short: "Read TPM NVRAM content",
		Long: `Use this command to read TPM resources(nvram, pcr, etc) and save to
file(Default: StdOut) with the define format(Default: PEM).
`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Println(cmd.Long)
				fmt.Println(cmd.UsageString())
				os.Exit(1)
			}
			obj := strings.ToUpper(args[0])
			if obj != constNVRAM && obj != constPCR {
				fmt.Println(cmd.Long)
				fmt.Println(cmd.UsageString())
				os.Exit(1)
			}
			if index == 0 {
				index = ractools.IndexRsa2048EKCert
			}
			if typ == "" {
				typ = constPEM
			}
			typ = strings.ToUpper(typ)
			tp, err := ractools.OpenTPM(!sim)
			if err != nil {
				fmt.Printf("can't open TPM, %v\n", err)
			}
			defer tp.Close()
			buf, err := tp.ReadEKCert(index)
			if err != nil {
				switch obj {
				case constNVRAM:
					fmt.Printf(errReadNVRAM, index, err)
				case constPCR:
					fmt.Printf(errReadPCR, index, err)
				}
				os.Exit(1)
			}
			if file == "" {
				switch obj {
				case constNVRAM:
					fmt.Printf(constWriteNVRAM, index, buf)
				case constPCR:
					fmt.Printf(constWritePCR, index, buf)
				}
			} else {
				ioutil.WriteFile(file, buf, 0644)
			}
		},
	}
	index uint32
	file  string
	typ   string
	sim   bool
)

func init() {
	rootCmd.AddCommand(readCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// readCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// readCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	readCmd.Flags().Uint32VarP(&index, "index", "i", 0, constIndexHelp)
	readCmd.Flags().StringVarP(&file, "file", "f", "", "the file to write content into")
	readCmd.Flags().StringVarP(&typ, "type", "t", "", "the output type PEM/DER (DEFAULT: PEM)")
	readCmd.Flags().BoolVarP(&sim, "simulator", "s", false, "use the simulator to test (DEFAULT: false)")
}
