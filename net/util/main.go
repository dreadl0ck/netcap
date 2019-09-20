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

package util

import (
	"fmt"
	"os"

	"github.com/dreadl0ck/netcap/utils"
	"github.com/spf13/cobra"
)

func GetCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "util",
		Short: "General utility tool",
		Long:  `General utility for working with netcap files`,
		Run: func(cmd *cobra.Command, args []string) {

			if flagConvertTimeToUTC != "" {
				fmt.Println(utils.TimeToUTC(flagConvertTimeToUTC))
				os.Exit(0)
			}

			if flagCheckFields {
				checkFields(flagInput)
				os.Exit(0)
			}
		},
	}

	cmd.Flags().StringVarP(&flagInput, "read", "r", "", "specify input file")
	cmd.MarkFlagRequired("read")

	cmd.Flags().BoolVarP(&flagCheckFields, "check", "c", false, "check fields")
	cmd.Flags().StringVarP(&flagConvertTimeToUTC, "ts2utc", "t", "", "convert a netcap timestamp to utc time")
	cmd.Flags().StringVarP(&flagSeparator, "separator", "s", "", "specify the separator used in the csv")

	return cmd
}
