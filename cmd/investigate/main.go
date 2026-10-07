package investigate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/flow"
	"github.com/urfave/cli/v3"
)

func GetCommand() *cli.Command {
	return &cli.Command{Name: "investigate", Usage: "bounded flow queries and verifiable packet evidence", Commands: []*cli.Command{
		{Name: "flows", Usage: "rank Connection observations with explicit snapshot/count semantics", Flags: []cli.Flag{
			&cli.StringFlag{Name: "read", Required: true, Usage: "Connection.ncap or Connection.ncap.gz"},
			&cli.StringFlag{Name: "start-ns", Required: true, Usage: "inclusive UTC nanosecond start; counters cover whole overlapping observations"},
			&cli.StringFlag{Name: "end-ns", Required: true, Usage: "inclusive UTC nanosecond end"},
			&cli.StringFlag{Name: "filter", Usage: "typed Connection expression (AND, OR, inversion and network helpers)"},
			&cli.StringFlag{Name: "group-by", Value: "srcIP", Usage: "srcIP, dstIP, dstPort, pair or protocol"},
			&cli.StringFlag{Name: "sort-by", Value: "bytes", Usage: "bytes, packets, peers, duration or rate"},
			&cli.IntFlag{Name: "limit", Value: 100, Usage: "returned groups (1..1000)"},
			&cli.DurationFlag{Name: "timeout", Value: 2 * time.Minute, Usage: "maximum query duration"},
		}, Action: runFlows},
		{Name: "packet-evidence", Usage: "export PCAPNG and provenance manifest in a ZIP archive", Flags: []cli.Flag{
			&cli.StringFlag{Name: "read", Required: true, Usage: "original PCAP or PCAPNG"},
			&cli.StringFlag{Name: "out", Required: true, Usage: "new output ZIP; existing files are never replaced"},
			&cli.StringFlag{Name: "bpf", Value: "len >= 0", Usage: "packet selection expression"},
			&cli.StringFlag{Name: "start-ns", Usage: "inclusive capture-time lower bound (requires end-ns)"},
			&cli.StringFlag{Name: "end-ns", Usage: "inclusive capture-time upper bound (requires start-ns)"},
			&cli.IntFlag{Name: "max-packets", Value: 1000000, Usage: "fail rather than silently truncate this many selected packets"},
			&cli.DurationFlag{Name: "timeout", Value: 2 * time.Minute, Usage: "maximum export duration"},
		}, Action: runPacketEvidence},
	}}
}

func runFlows(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 0 {
		return fmt.Errorf("flows does not accept positional arguments")
	}
	q, err := flow.ParseQuery(url.Values{"startNs": {cmd.String("start-ns")}, "endNs": {cmd.String("end-ns")},
		"filter": {cmd.String("filter")}, "groupBy": {cmd.String("group-by")}, "sortBy": {cmd.String("sort-by")}, "limit": {strconv.Itoa(cmd.Int("limit"))}})
	if err != nil {
		return err
	}
	if cmd.Duration("timeout") <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, cmd.Duration("timeout"))
	defer cancel()
	result, err := flow.ReadFile(ctx, cmd.String("read"), q)
	if err != nil {
		return err
	}
	return json.NewEncoder(cmd.Root().Writer).Encode(result)
}

func runPacketEvidence(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 0 {
		return fmt.Errorf("packet-evidence does not accept positional arguments")
	}
	selection := evidence.Selection{BPF: cmd.String("bpf"), MaxPackets: cmd.Int("max-packets")}
	if cmd.IsSet("start-ns") != cmd.IsSet("end-ns") {
		return fmt.Errorf("start-ns and end-ns must be supplied together")
	}
	if cmd.IsSet("start-ns") {
		start, err := strconv.ParseInt(cmd.String("start-ns"), 10, 64)
		if err != nil {
			return err
		}
		end, err := strconv.ParseInt(cmd.String("end-ns"), 10, 64)
		if err != nil {
			return err
		}
		selection.StartNs, selection.EndNs = &start, &end
	}
	if cmd.Duration("timeout") <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, cmd.Duration("timeout"))
	defer cancel()
	manifest, err := evidence.ArchiveToFile(ctx, cmd.String("read"), cmd.String("out"), selection)
	if err != nil {
		return err
	}
	return json.NewEncoder(cmd.Root().Writer).Encode(manifest)
}
