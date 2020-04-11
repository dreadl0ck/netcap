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
	"os"
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