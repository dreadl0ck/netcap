package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/dreadl0ck/netcap/cmd/capture"
	"github.com/urfave/cli/v3"
)

func main() {
	command := &cli.Command{Name: "capture", Flags: capture.GetFlags(), Action: func(ctx context.Context, c *cli.Command) error {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"paths": c.StringSlice("proto-paths"), "mappings": c.StringSlice("proto-message-types"), "dpi": c.Bool("dpi"), "payload": c.Bool("payload"), "retentionMB": c.Int64("packet-retention-mb"), "modules": c.String("dpi-modules"), "bpf": c.String("bpf"), "include": c.String("include"), "exclude": c.String("exclude")})
	}}
	if err := command.Run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
