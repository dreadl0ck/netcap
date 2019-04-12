package main

import (
	"flag"
	"log"

	"github.com/dreadl0ck/netcap/label"
)

var (
	flagDebug     = flag.Bool("debug", false, "toggle debug mode")
	flagInput     = flag.String("r", "", "(required) read specified file, can either be a pcap or netcap audit record file")
	flagSeparator = flag.String("sep", ",", "set separator string for csv output")
	flagOutDir    = flag.String("out", "", "specify output directory, will be created if it does not exist")

	flagDescription           = flag.Bool("description", false, "use attack description instead of classification for labels")
	flagProgressBars          = flag.Bool("progress", false, "use progress bars")
	flagStopOnDuplicateLabels = flag.Bool("strict", false, "fail when there is more than one alert for the same timestamp")
	flagExcludeLabels         = flag.String("exclude", "", "specify a comma separated list of suricata classifications that shall be excluded from the generated labeled csv")
	flagCollectLabels         = flag.Bool("collect", false, "append classifications from alert with duplicate timestamps to the generated label")
	flagDisableLayerMapping   = flag.Bool("disable-layers", false, "do not map layer types by timestamp")

	// this wont work currently, because the Select() func will stop if there are fields that are not present on an audit record
	// as labeling iterates over all available records, there will always be a record that does not have all selected fields
	// TODO: create a func that ignores fields that do not exist on the target audit record, maybe Select() and SelectStrict()
	// flagSelect    = flag.String("select", "", "select specific fields of an audit records when generating csv or tables")
)

func main() {

	// parse flags
	flag.Parse()

	if *flagInput == "" {
		log.Fatal("no input file specified. Nothing to do.")
	}

	label.Debug = *flagDebug

	// configure
	label.DisableLayerMapping = *flagDisableLayerMapping
	label.UseProgressBars = *flagProgressBars
	label.StopOnDuplicateLabels = *flagStopOnDuplicateLabels
	label.CollectLabels = *flagCollectLabels
	label.SetExcluded(*flagExcludeLabels)

	// lets go
	log.Fatal(label.Suricata(*flagInput, *flagOutDir, *flagDescription, *flagSeparator, ""))
}
