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
	"strings"
)

var flagCompletions = flag.String("completions", "", "get available command completions")

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

	if *flagCompletions != "" {
		printCompletions(*flagCompletions)
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
	case "help", "-h", "--help":
		help()
	}
}

// print available completions for the bash-completion package
func printCompletions(previous string) {

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

	// show flags for subcommands
	switch previous {
		case "capture":
			saveSubCmd("capture")
			printFlags(capture.Flags())
		case "util":
			saveSubCmd("util")
			printFlags(util.Flags())
		case "proxy":
			saveSubCmd("proxy")
			printFlags(proxy.Flags())
		case "label":
			saveSubCmd("label")
			printFlags(label.Flags())
		case "export":
			saveSubCmd("export")
			printFlags(export.Flags())
		case "dump":
			saveSubCmd("dump")
			printFlags(dump.Flags())
		case "collect":
			saveSubCmd("collect")
			printFlags(collect.Flags())
		case "help":
			saveSubCmd("")
		case "transform":
			saveSubCmd("")
			return
	}

	// the user could be in the middle of typing a command.
	// load the current command from the cache
	// and show all flags except for the last one
	if previous != "net" {
		switch loadSubCmd() {
		case "capture":
			printFlagsFiltered(capture.Flags(), previous)
		case "util":
			printFlagsFiltered(util.Flags(), previous)
		case "proxy":
			printFlagsFiltered(proxy.Flags(), previous)
		case "label":
			printFlagsFiltered(label.Flags(), previous)
		case "export":
			printFlagsFiltered(export.Flags(), previous)
		case "dump":
			printFlagsFiltered(dump.Flags(), previous)
		case "collect":
			printFlagsFiltered(collect.Flags(), previous)
		}
	}

	// print subcommands
	for _, name := range completions {
		fmt.Print(name + " ")
	}
	fmt.Println()
}

func printFlags(arr []string) {
	for _, f := range arr {
		fmt.Print("-" + f + " ")
	}
	fmt.Println()
	os.Exit(0)
}

func printFlagsFiltered(arr []string, hide string) {
	hide = strings.TrimPrefix(hide, "-")
	for _, f := range arr {
		if f != hide {
			fmt.Print("-" + f + " ")
		}
	}
	fmt.Println()
	os.Exit(0)
}

func saveSubCmd(cmd string) {
	f, err := os.Create("/usr/local/etc/netcap/.completion-cache")
	if err != nil {
		log.Fatal("failed to create bash completion cache file: ", err)
	}
	f.WriteString(cmd)
	err = f.Close()
	if err != nil {
		log.Fatal("failed to close bash completion cache file: ", err)
	}
}

func loadSubCmd() string {
	c, err := ioutil.ReadFile("/usr/local/etc/netcap/.completion-cache")
	if err != nil {
		log.Fatal("failed to load bash completion cache file: ", err)
	}
	return string(c)
}