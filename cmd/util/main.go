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

package util

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/dbs"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

// Global context for helper functions
var currentCtx *cli.Command

// Run parses the subcommand flags and handles the arguments.
// This is a compatibility wrapper for the old Run() interface.
func Run() {
	// Remove date/time from log output to prevent duplicate timestamps
	// when running in Docker/systemd (which add their own timestamps)
	log.SetFlags(0)

	// Create a new CLI app just for parsing flags
	cmd := &cli.Command{
		Name:  "util",
		Usage: "general utility tool",
		Flags: GetFlags(),
		Action: func(ctx context.Context, c *cli.Command) error {
			return RunWithContext(ctx, c)
		},
	}

	if err := cmd.Run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// RunWithContext runs the util command with a CLI context.
func RunWithContext(ctx context.Context, c *cli.Command) error {
	// Store context for helper functions
	currentCtx = c

	if c.Bool("gen-config") {
		// TODO: Update GenerateConfig to work with urfave/cli
		fmt.Println("gen-config not yet implemented with urfave/cli")
		return nil
	}

	if c.Bool("generate-dbs") {
		dbs.GenerateDBs(c.Int("nvd-start-year"))
		return nil
	}

	if c.Bool("update-dbs") {
		dbs.UpdateDBs()
		return nil
	}

	if c.Bool("download-geolite") {
		dbs.DownloadGeoLite()
		return nil
	}

	if c.Bool("serve-dbs") {
		server := dbs.NewDBServer(c.String("serve-addr"), c.Int("nvd-start-year"), c.Bool("verbose"))
		if err := server.Start(); err != nil {
			log.Fatal("failed to start database server: ", err)
		}
		return nil
	}

	if c.Bool("download-dbs") {
		if err := dbs.DownloadDBs(c.String("dbs-url"), c.Bool("force")); err != nil {
			log.Fatal("failed to download databases: ", err)
		}
		return nil
	}

	// Simple util to construct a IPv4 pcapng packet, with a TCP / UDP layer and a given payload.
	// Will add dummy values for the Ethernet and IPv4 layers.
	// Useful to dissect a specific TCP / UDP payload in wireshark, to compare the results with other tools.
	flagMkPacket := c.String("mkpacket")
	if flagMkPacket != "" {
		makePacket()
		return nil
	}

	// util to convert netcap timestamp to UTC time
	flagToUTC := c.String("ts2utc")
	if flagToUTC != "" {
		fmt.Println(utils.TimeToUTC(flagToUTC))
		return nil
	}

	// util to check if fields count matches for all generated rows
	if c.Bool("check") {
		checkFields()
		return nil
	}

	if c.Bool("env") {
		out, errEnv := exec.Command("env").CombinedOutput()
		if errEnv != nil {
			log.Fatal(errEnv)
		}

		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, defaults.NetcapTypePrefix) {
				fmt.Println(line)
			}
		}

		return nil
	}

	if c.Bool("interfaces") {
		utils.ListAllNetworkInterfaces()
		return nil
	}

	flagIndex := c.String("index")
	if flagIndex != "" {
		dbs.IndexData(flagIndex, resolvers.DataBaseFolderPath, resolvers.DataBaseBuildPath, c.Int("nvd-start-year"), c.Bool("verbose"))
		return nil
	}

	if c.Bool("decoders") {
		printDecoders()
		return nil
	}

	if c.Bool("gopacket-coverage") {
		analyzeGoPacketCoverage()
		return nil
	}

	printHeader()
	return nil
}
