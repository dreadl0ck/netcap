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
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/cmd/capture"
	"github.com/dreadl0ck/netcap/cmd/collect"
	"github.com/dreadl0ck/netcap/cmd/dump"
	"github.com/dreadl0ck/netcap/cmd/export"
	"github.com/dreadl0ck/netcap/cmd/label"
	"github.com/dreadl0ck/netcap/cmd/proxy"
	"github.com/dreadl0ck/netcap/cmd/transform"
	"github.com/dreadl0ck/netcap/cmd/util"
	"github.com/namsral/flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var (
	flagPrevious = flag.String("previous", "", "internal for bash-completion")
	flagCurrent  = flag.String("current", "", "internal for bash-completion")
	flagFull     = flag.String("full", "", "internal for bash-completion")
	flagVersion  = flag.Bool("version", false, "print version")
)

func help() {
	netcap.PrintLogo()
	fmt.Println(`
available subcommands:
  > capture       capture audit records
  > util          general util toool
  > proxy         http proxy
  > label         apply labels to audit records
  > export        exports audit records
  > dump          utility to read audit record files
  > collect       collector for audit records from agents
  > transform     maltego plugin
  > help          display this help

usage: ./net <subcommand> [flags]
or: ./net <subcommand> [-h] to get help for the subcommand`)
	os.Exit(0)
}

func main() {

	flag.Usage = help
	flag.Parse()

	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

	if *flagPrevious != "" {
		printCompletions(*flagPrevious, *flagCurrent, *flagFull)
		return
	}

	if len(os.Args) < 2 {
		help()
	}
	switch os.Args[1] {
	case "capture":
		capture.Run()
	case "util":
		util.Run()
	case "proxy":
		proxy.Run()
	case "label":
		label.Run()
	case "export":
		export.Run()
	case "dump":
		dump.Run()
	case "collect":
		collect.Run()
	case "transform":
		transform.Run()
	case "version":
		fmt.Println(netcap.Version)
	case "help", "-h", "--help":
		help()
	}
}

// print builtins
var completions = []string{
	"capture",
	"util",
	"proxy",
	"label",
	"export",
	"dump",
	"collect",
	"transform",
	"help",
}

var debugHandle = ioutil.Discard

func debug(args ...interface{}) {
	fmt.Fprintln(debugHandle, args...)
}

// print available completions for the bash-completion package
func printCompletions(previous, current, full string) {

	if os.Getenv("NC_COMPLETION_DEBUG") == "1" {
		var err error
		debugHandle, err = os.OpenFile("completion-debug.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0744)
		if err != nil {
			log.Fatal(err)
		}
	}

	debug("previous:", previous, "current:", current, "full:", full)

	// show flags for subcommands
	switch previous {
	case "capture":
		printFlags(capture.Flags())
	case "util":
		printFlags(util.Flags())
	case "proxy":
		printFlags(proxy.Flags())
	case "label":
		printFlags(label.Flags())
	case "export":
		printFlags(export.Flags())
	case "dump":
		printFlags(dump.Flags())
	case "collect":
		printFlags(collect.Flags())
	case "help":
	case "transform":
		return
	}

	// the user could be in the middle of typing a command.
	// determine the current command and show all flags except for the last one
	if previous != "net" {
		subCmd := getSubCmd(full)
		debug("subcommand:", subCmd)
		switch subCmd {
		case "capture":
			if previous == "-read" {
				printFileForExt(".pcap", ".pcapng")
			}
			handleConfigFlag()
			printFlagsFiltered(capture.Flags())
		case "util":
			if previous == "-read" {
				printFileForExt(".ncap", ".gz")
			}
			handleConfigFlag()
			printFlagsFiltered(util.Flags())
		case "proxy":
			handleConfigFlag()
			printFlagsFiltered(proxy.Flags())
		case "label":
			if previous == "-read" {
				printFileForExt(".pcap", ".pcapng")
			}
			if previous == "-custom" {
				printFileForExt(".csv")
			}
			handleConfigFlag()
			printFlagsFiltered(label.Flags())
		case "export":
			if previous == "-read" {
				printFileForExt(".ncap", ".gz", ".pcap", ".pcapng")
			}
			handleConfigFlag()
			printFlagsFiltered(export.Flags())
		case "dump":
			if previous == "-read" {
				printFileForExt(".ncap", ".gz")
			}
			handleConfigFlag()
			printFlagsFiltered(dump.Flags())
		case "collect":
			handleConfigFlag()
			printFlagsFiltered(collect.Flags())
		}
	}

	// print subcommands
	for _, name := range completions {
		fmt.Print(name + " ")
	}
	fmt.Println()
}

func handleConfigFlag() {
	if *flagPrevious == "-config" {
		printFileForExt(".conf")
	}
}

func printFileForExt(exts ...string) {

	var path = "."
	var currBase string
	if *flagCurrent != "" {
		currBase = filepath.Dir(*flagCurrent)
		if s, err := os.Stat(currBase); err == nil {
			if s.IsDir() {
				debug("setting path to", currBase)
				path = currBase
			}
		}
	}
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}

	//debug("got", len(files), "results")

	for _, f := range files {
		for _, e := range exts {
			if f.IsDir() || filepath.Ext(f.Name()) == e {
				path := filepath.Join(currBase, f.Name())
				if f.IsDir() {
					path += "/"
				}
				fmt.Print(path + " ")
				//debug("output", path)
				break
			}
		}
	}
	fmt.Println()
	os.Exit(0)
}

func printFlags(arr []string) {
	for _, f := range arr {
		fmt.Print("-" + f + " ")
	}
	fmt.Println()
	os.Exit(0)
}

func printFlagsFiltered(arr []string) {

	var hide = make(map[string]struct{})
	for _, f := range strings.Fields(*flagFull) {
		if strings.HasPrefix(f, "-") {
			hide[strings.TrimPrefix(f, "-")] = struct{}{}
		}
	}

	for _, f := range arr {
		if _, shouldHide := hide[f]; !shouldHide {
			fmt.Print("-" + f + " ")
		}
	}

	fmt.Println()
	os.Exit(0)
}

func getSubCmd(full string) string {
	fields := strings.Fields(full)
	if len(fields) < 2 {
		return ""
	}

	return fields[1]
}
