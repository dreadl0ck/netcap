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
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/label"
)

func main() {

	// parse commandline flags
	flag.Usage = printUsage
	flag.Parse()

	// print version and exit
	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

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
		log.Fatal(label.CustomLabels(*flagCustom, *flagOutDir, *flagDescription, *flagSeparator, ""))
	} else {
		log.Fatal(label.Suricata(*flagInput, *flagOutDir, *flagDescription, *flagSeparator, ""))
	}
}
