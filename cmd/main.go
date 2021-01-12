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

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"flag"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/cmd/agent"
	"github.com/dreadl0ck/netcap/cmd/capture"
	"github.com/dreadl0ck/netcap/cmd/collect"
	"github.com/dreadl0ck/netcap/cmd/dump"
	"github.com/dreadl0ck/netcap/cmd/export"
	"github.com/dreadl0ck/netcap/cmd/label"
	"github.com/dreadl0ck/netcap/cmd/proxy"
	"github.com/dreadl0ck/netcap/cmd/transform"
	"github.com/dreadl0ck/netcap/cmd/util"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/env"
	"github.com/dreadl0ck/netcap/io"
)

const (
	cmdCapture   = "capture"
	cmdUtil      = "util"
	cmdProxy     = "proxy"
	cmdLabel     = "label"
	cmdExport    = "export"
	cmdDump      = "dump"
	cmdCollect   = "collect"
	cmdTransform = "transform"
	cmdAgent     = "agent"
	cmdVersion   = "version"
	cmdHelp      = "help"

	nameReadFlag   = "-read"
	nameConfigFlag = "-config"

	extPCAP   = ".pcap"
	extPCAPNG = ".pcapng"
	extConfig = ".conf"
	extNetcap = defaults.FileExtension
	extGzip   = ".gz"
)

var (
	flagPrevious = flag.String("previous", "", "internal for bash-completion")
	flagCurrent  = flag.String("current", "", "internal for bash-completion")
	flagFull     = flag.String("full", "", "internal for bash-completion")
	flagVersion  = flag.Bool(cmdVersion, false, "print version")
)

func help() {
	io.PrintLogo()
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
	case cmdCapture:
		capture.Run()
	case cmdUtil:
		util.Run()
	case cmdProxy:
		proxy.Run()
	case cmdLabel:
		label.Run()
	case cmdExport:
		export.Run()
	case cmdDump:
		dump.Run()
	case cmdCollect:
		collect.Run()
	case cmdTransform:
		transform.Run()
	case cmdAgent:
		agent.Run()
	case cmdVersion:
		fmt.Println(netcap.Version)
	case cmdHelp, "-h", "--help":
		help()
	}
}

// print builtins.
var completions = []string{
	cmdCapture,
	cmdUtil,
	cmdProxy,
	cmdLabel,
	cmdExport,
	cmdDump,
	cmdCollect,
	cmdTransform,
	cmdHelp,
	cmdAgent,
	cmdVersion,
}

var debugHandle = ioutil.Discard

func debug(args ...interface{}) {
	_, _ = fmt.Fprintln(debugHandle, args...)
}

// print available completions for the bash-completion package.
func printCompletions(previous, current, full string) {
	if os.Getenv(env.CompletionDebug) == "1" {
		var err error

		debugHandle, err = os.OpenFile("completion-debug.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o744)
		if err != nil {
			log.Fatal(err)
		}
	}

	debug("previous:", previous, "current:", current, "full:", full)

	// show flags for subcommands
	switch previous {
	case cmdCapture:
		printFlags(capture.Flags())
	case cmdUtil:
		printFlags(util.Flags())
	case cmdProxy:
		printFlags(proxy.Flags())
	case cmdLabel:
		printFlags(label.Flags())
	case cmdExport:
		printFlags(export.Flags())
	case cmdDump:
		printFlags(dump.Flags())
	case cmdCollect:
		printFlags(collect.Flags())
	case cmdAgent:
		printFlags(agent.Flags())
	case cmdHelp:
	case cmdTransform:
		return
	}

	// the user could be in the middle of typing a command.
	// determine the current command and show all flags except for the last one
	if previous != "net" {
		subCmd := getSubCmd(full)
		debug("subcommand:", subCmd)

		switch subCmd {
		case cmdCapture:
			if previous == nameReadFlag {
				printFileForExt(extPCAP, extPCAPNG)
			}

			handleConfigFlag()
			printFlagsFiltered(capture.Flags())
		case cmdUtil:
			if previous == nameReadFlag {
				printFileForExt(extNetcap, extGzip)
			}

			handleConfigFlag()
			printFlagsFiltered(util.Flags())
		case cmdProxy:
			handleConfigFlag()
			printFlagsFiltered(proxy.Flags())
		case cmdLabel:
			if previous == nameReadFlag {
				printFileForExt(extPCAP, extPCAPNG)
			}

			if previous == "-custom" {
				printFileForExt(".csv")
			}

			handleConfigFlag()
			printFlagsFiltered(label.Flags())
		case cmdExport:
			if previous == nameReadFlag {
				printFileForExt(extNetcap, extGzip, extPCAP, extPCAPNG)
			}

			handleConfigFlag()
			printFlagsFiltered(export.Flags())
		case cmdDump:
			if previous == nameReadFlag {
				printFileForExt(extNetcap, extGzip)
			}

			handleConfigFlag()
			printFlagsFiltered(dump.Flags())
		case cmdCollect:
			handleConfigFlag()
			printFlagsFiltered(collect.Flags())
		case cmdAgent:
			handleConfigFlag()
			printFlagsFiltered(agent.Flags())
		}
	}

	// print subcommands
	for _, name := range completions {
		fmt.Print(name + " ")
	}

	fmt.Println()
}

func handleConfigFlag() {
	if *flagPrevious == nameConfigFlag {
		printFileForExt(extConfig)
	}
}

func printFileForExt(exts ...string) {
	var (
		path     = "."
		currBase string
	)

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

	for _, f := range files {
		for _, e := range exts {
			if f.IsDir() || filepath.Ext(f.Name()) == e {
				p := filepath.Join(currBase, f.Name())
				if f.IsDir() {
					p += "/"
				}

				fmt.Print(p + " ")

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
	hide := make(map[string]struct{})

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
