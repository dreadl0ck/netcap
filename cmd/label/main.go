/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	"os"

	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/label"
)

// Run parses the subcommand flags and handles the arguments.
func Run() {
	// parse commandline flags
	fs.Usage = printUsage
	err := fs.Parse(os.Args[2:])
	if err != nil {
		log.Fatal(err)
	}

	if *flagGenerateConfig {
		io.GenerateConfig(fs, "label")

		return
	}

	io.PrintBuildInfo()

	if *flagInput == "" && *flagCustom == "" {
		log.Fatal("no input file specified. Nothing to do.")
	}

	label.Debug = *flagDebug

	// configure
	label.SuricataConfigPath = *flagSuricataConfigPath
	label.DisableLayerMapping = *flagDisableLayerMapping
	label.UseProgressBars = *flagProgressBars
	label.StopOnDuplicateLabels = *flagStopOnDuplicateLabels
	label.CollectLabels = *flagCollectLabels
	label.SetExcluded(*flagExcludeLabels)

	// lets go
	if *flagCustom != "" {
		err = label.CustomLabels(*flagCustom, *flagOutDir, *flagSeparator, "")
	} else {
		err = label.Suricata(*flagInput, *flagOutDir, *flagDescription, *flagSeparator, "")
	}
	if err != nil {
		log.Fatal(err)
	}
}
