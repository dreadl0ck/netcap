package main

import "flag"

var (
	flagAddress  = flag.String("address", "127.0.0.1:7777", "set address for exposing metrics")
	flagDumpJSON = flag.Bool("dumpJson", false, "dump as JSON")
	flagQuiet    = flag.Bool("quiet", false, "dont print logo only output")
	flagRead     = flag.String("r", "", "input netcap audit recod file")
	flagReplay   = flag.Bool("replay", true, "replay traffic")
)
