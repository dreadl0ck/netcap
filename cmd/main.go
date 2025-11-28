/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/cmd/agent"
	"github.com/dreadl0ck/netcap/cmd/capture"
	"github.com/dreadl0ck/netcap/cmd/collect"
	"github.com/dreadl0ck/netcap/cmd/dump"
	"github.com/dreadl0ck/netcap/cmd/export"
	"github.com/dreadl0ck/netcap/cmd/inject"
	"github.com/dreadl0ck/netcap/cmd/label"
	"github.com/dreadl0ck/netcap/cmd/proxy"
	"github.com/dreadl0ck/netcap/cmd/transform"
	"github.com/dreadl0ck/netcap/cmd/util"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/env"
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
	cmdInject    = "inject"
	cmdVersion   = "version"

	nameReadFlag   = "-read"
	nameConfigFlag = "-config"

	extPCAP   = ".pcap"
	extPCAPNG = ".pcapng"
	extConfig = ".conf"
	extNetcap = defaults.FileExtension
	extGzip   = ".gz"
)

func main() {
	// Remove date/time from log output to prevent duplicate timestamps
	// when running in Docker/systemd (which add their own timestamps)
	log.SetFlags(0)

	// Check for bash completion mode (legacy support)
	if len(os.Args) > 1 && (os.Args[1] == "-previous" || os.Args[1] == "--previous") {
		handleLegacyCompletion()
		return
	}

	app := &cli.Command{
		Name:                  "net",
		Usage:                 "NETCAP - Network Capture and Analysis Framework",
		EnableShellCompletion: true,
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			if cmd.Bool("version") {
				io.PrintBuildInfo()
				os.Exit(0)
			}
			return ctx, nil
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "version",
				Aliases: []string{"v"},
				Usage:   "print version information",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  cmdCapture,
				Usage: "capture audit records from network traffic",
				Flags: capture.GetFlags(),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return capture.RunWithContext(ctx, cmd)
				},
			},
			{
				Name:  cmdUtil,
				Usage: "general utility tool",
				Flags: util.GetFlags(),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return util.RunWithContext(ctx, cmd)
				},
			},
			{
				Name:  cmdProxy,
				Usage: "HTTP proxy for traffic inspection",
				Flags: proxy.GetFlags(),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return proxy.RunWithContext(ctx, cmd)
				},
			},
			{
				Name:  cmdLabel,
				Usage: "apply labels to audit records",
				Flags: label.GetFlags(),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return label.RunWithContext(ctx, cmd)
				},
			},
			{
				Name:  cmdExport,
				Usage: "export audit records",
				Flags: export.GetFlags(),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return export.RunWithContext(ctx, cmd)
				},
			},
			{
				Name:  cmdDump,
				Usage: "utility to read audit record files",
				Flags: dump.GetFlags(),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return dump.RunWithContext(ctx, cmd)
				},
			},
			{
				Name:  cmdCollect,
				Usage: "collector for audit records from agents",
				Flags: collect.GetFlags(),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return collect.RunWithContext(ctx, cmd)
				},
			},
			{
				Name:  cmdTransform,
				Usage: "maltego plugin",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					transform.Run()
					return nil
				},
			},
			{
				Name:  cmdAgent,
				Usage: "agent for distributed capture",
				Flags: agent.GetFlags(),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return agent.RunWithContext(ctx, cmd)
				},
			},
			{
				Name:  cmdInject,
				Usage: "inline packet manipulation (MITM mode, Linux only)",
				Flags: inject.GetFlags(),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return inject.RunWithContext(ctx, cmd)
				},
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			io.PrintLogo()
			fmt.Println(`
available subcommands:
  > capture       capture audit records
  > util          general util tool
  > proxy         http proxy
  > label         apply labels to audit records
  > export        exports audit records
  > dump          utility to read audit record files
  > collect       collector for audit records from agents
  > transform     maltego plugin
  > agent         agent for distributed capture
  > inject        inline packet manipulation (MITM mode, Linux only)

usage: ./net <subcommand> [flags]
or: ./net <subcommand> [-h] to get help for the subcommand`)
			return nil
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

// handleLegacyCompletion handles bash completion using the old flag-based system.
// This preserves backward compatibility with existing bash completion scripts.
func handleLegacyCompletion() {
	var flagPrevious, flagCurrent, flagFull string

	// Parse legacy completion flags
	for i, arg := range os.Args {
		if arg == "-previous" || arg == "--previous" {
			if i+1 < len(os.Args) {
				flagPrevious = os.Args[i+1]
			}
		}
		if arg == "-current" || arg == "--current" {
			if i+1 < len(os.Args) {
				flagCurrent = os.Args[i+1]
			}
		}
		if arg == "-full" || arg == "--full" {
			if i+1 < len(os.Args) {
				flagFull = os.Args[i+1]
			}
		}
	}

	if flagPrevious != "" {
		printCompletions(flagPrevious, flagCurrent, flagFull)
	}
}

var debugHandle = ioutil.Discard

func debug(args ...interface{}) {
	_, _ = fmt.Fprintln(debugHandle, args...)
}

// print available completions for the bash-completion package.
func printCompletions(previous, current, full string) {
	// print builtins
	completions := []string{
		cmdCapture,
		cmdUtil,
		cmdProxy,
		cmdLabel,
		cmdExport,
		cmdDump,
		cmdCollect,
		cmdTransform,
		cmdAgent,
		cmdInject,
	}

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
	case cmdInject:
		printFlags(inject.Flags())
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
				printFileForExt(current, extPCAP, extPCAPNG)
			}

			handleConfigFlag(previous, current)
			printFlagsFiltered(capture.Flags(), full)
		case cmdUtil:
			if previous == nameReadFlag {
				printFileForExt(current, extNetcap, extGzip)
			}

			handleConfigFlag(previous, current)
			printFlagsFiltered(util.Flags(), full)
		case cmdProxy:
			handleConfigFlag(previous, current)
			printFlagsFiltered(proxy.Flags(), full)
		case cmdLabel:
			if previous == nameReadFlag {
				printFileForExt(current, extPCAP, extPCAPNG)
			}

			if previous == "-custom" {
				printFileForExt(current, ".csv")
			}

			handleConfigFlag(previous, current)
			printFlagsFiltered(label.Flags(), full)
		case cmdExport:
			if previous == nameReadFlag {
				printFileForExt(current, extNetcap, extGzip, extPCAP, extPCAPNG)
			}

			handleConfigFlag(previous, current)
			printFlagsFiltered(export.Flags(), full)
		case cmdDump:
			if previous == nameReadFlag {
				printFileForExt(current, extNetcap, extGzip)
			}

			handleConfigFlag(previous, current)
			printFlagsFiltered(dump.Flags(), full)
		case cmdCollect:
			handleConfigFlag(previous, current)
			printFlagsFiltered(collect.Flags(), full)
		case cmdAgent:
			handleConfigFlag(previous, current)
			printFlagsFiltered(agent.Flags(), full)
		case cmdInject:
			if previous == "-rules" {
				printFileForExt(current, ".yml", ".yaml")
			}
			handleConfigFlag(previous, current)
			printFlagsFiltered(inject.Flags(), full)
		}
	}

	// print subcommands
	for _, name := range completions {
		fmt.Print(name + " ")
	}

	fmt.Println()
}

func handleConfigFlag(previous, current string) {
	if previous == nameConfigFlag {
		printFileForExt(current, extConfig)
	}
}

func printFileForExt(current string, exts ...string) {
	var (
		path     = "."
		currBase string
	)

	if current != "" {
		currBase = filepath.Dir(current)
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

func printFlagsFiltered(arr []string, full string) {
	hide := make(map[string]struct{})

	for _, f := range strings.Fields(full) {
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
