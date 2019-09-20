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

package label

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/dreadl0ck/netcap/label"
)

func GetCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "label",
		Short: "Dataset labeling tool",
		Run: func(cmd *cobra.Command, args []string) {

			if flagInput == "" {
				log.Fatal("no input file specified. Nothing to do.")
			}

			label.Debug = flagDebug

			// configure
			label.SuricataConfigPath = flagSuricataConfigPath
			label.DisableLayerMapping = flagDisableLayerMapping
			label.UseProgressBars = flagProgressBars
			label.StopOnDuplicateLabels = flagStopOnDuplicateLabels
			label.CollectLabels = flagCollectLabels
			label.SetExcluded(flagExcludeLabels)

			// lets go
			log.Fatal(label.Suricata(flagInput, flagOutDir, flagDescription, flagSeparator, ""))
		},
	}

	cmd.Flags().StringVarP(&flagInput, "read", "r", "", "specify input file")
	cmd.MarkFlagRequired("read")

	cmd.Flags().BoolVarP(&flagDebug, "debug", "d", false, "debug mode")
	cmd.Flags().StringVarP(&flagSeparator, "separator", "s", "", "specify the separator used in the csv")
	cmd.Flags().StringVarP(&flagOutDir, "out", "o", "", "set out dir")

	cmd.Flags().BoolVarP(&flagDescription, "description", "", false, "use attack description")
	cmd.Flags().BoolVarP(&flagProgressBars, "progress", "p", false, "show progress pars")
	cmd.Flags().BoolVarP(&flagStopOnDuplicateLabels, "strict", "", false, "strict mode")

	cmd.Flags().BoolVarP(&flagCollectLabels, "collect", "c", false, "collect labels")
	cmd.Flags().BoolVarP(&flagDisableLayerMapping, "disable-lm", "", false, "disable layer mapping")

	cmd.Flags().StringVarP(&flagExcludeLabels, "exclude", "e", "", "exclude labels")
	cmd.Flags().StringVarP(&flagSuricataConfigPath, "suricata-config", "", "", "set path to suricata config file")

	return cmd
}
