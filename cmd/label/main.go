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
	"context"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/label"
)

// Run parses the subcommand flags and handles the arguments.
// This is a compatibility wrapper for the old Run() interface.
func Run() {
	// Remove date/time from log output to prevent duplicate timestamps
	// when running in Docker/systemd (which add their own timestamps)
	log.SetFlags(0)

	// Create a new CLI app just for parsing flags
	cmd := &cli.Command{
		Name:  "label",
		Usage: "apply labels to audit records",
		Flags: GetFlags(),
		Action: func(ctx context.Context, c *cli.Command) error {
			return RunWithContext(ctx, c)
		},
	}

	if err := cmd.Run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// RunWithContext runs the label command with a CLI context.
func RunWithContext(ctx context.Context, c *cli.Command) error {
	if c.Bool("gen-config") {
		// TODO: Update GenerateConfig to work with urfave/cli
		fmt.Println("gen-config not yet implemented with urfave/cli")
		return nil
	}

	io.PrintBuildInfo()

	flagInput := c.String("read")
	flagCustom := c.String("custom")

	if flagInput == "" && flagCustom == "" {
		log.Fatal("no input file specified. Nothing to do.")
	}

	label.Debug = c.Bool("debug")

	// configure
	label.SuricataConfigPath = c.String("suricata-config")
	label.DisableLayerMapping = c.Bool("disable-layers")
	label.UseProgressBars = c.Bool("progress")
	label.StopOnDuplicateLabels = c.Bool("strict")
	label.CollectLabels = c.Bool("collect")
	label.SetExcluded(c.String("exclude"))

	// lets go
	var err error
	if flagCustom != "" {
		err = label.CustomLabels(flagCustom, c.String("out"), c.String("sep"), "")
	} else {
		err = label.Suricata(flagInput, c.String("out"), c.Bool("description"), c.String("sep"), "")
	}
	if err != nil {
		log.Fatal(err)
	}

	return nil
}
