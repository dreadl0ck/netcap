/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"fmt"
	"os"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/net/agent"
	"github.com/dreadl0ck/netcap/net/capture"
	"github.com/dreadl0ck/netcap/net/label"
	"github.com/dreadl0ck/netcap/net/proxy"
	"github.com/dreadl0ck/netcap/net/util"
	"github.com/spf13/cobra"
)

var (
	flagVersion bool
	rootCmd     = &cobra.Command{
		Use:   "net",
		Short: "Netcap traffic analysis framework",
		Long: `A secure and scalable framework for network traffic analysis.
					see: https://netcap.io`,
		Run: func(cmd *cobra.Command, args []string) {

			if flagVersion {
				fmt.Println(netcap.Version)
				os.Exit(0)
			}

			netcap.PrintLogo()
			err := cmd.Help()
			if err != nil {
				fmt.Println(err)
			}
		},
	}
)

func main() {

	// add subcommands
	rootCmd.AddCommand(label.GetCommand())
	rootCmd.AddCommand(util.GetCommand())
	rootCmd.AddCommand(proxy.GetCommand())
	rootCmd.AddCommand(agent.GetCommand())
	rootCmd.AddCommand(capture.GetCommand())

	// rootCmd.AddCommand(collect.GetCommand())
	// rootCmd.AddCommand(dump.GetCommand())
	// rootCmd.AddCommand(export.GetCommand())

	rootCmd.Flags().BoolVarP(&flagVersion, "version", "v", false, "Print NETCAP framework version and exit")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
