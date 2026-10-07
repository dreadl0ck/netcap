package investigate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/flow"
	"github.com/dreadl0ck/netcap/internal/flowexport"
	"github.com/dreadl0ck/netcap/internal/protocoltest"
	"github.com/urfave/cli/v3"
)

func GetCommand() *cli.Command {
	return &cli.Command{Name: "investigate", Usage: "bounded flow queries and verifiable packet evidence", Commands: []*cli.Command{
		{Name: "protocol-proxy", Usage: "proxy one framed TCP exchange with bounded message mutations", Flags: []cli.Flag{
			&cli.StringFlag{Name: "spec", Required: true, Usage: "JSON proxy specification (maximum 2 MiB)"},
			&cli.StringFlag{Name: "listen", Value: "127.0.0.1:0", Usage: "local TCP address; selected port is printed on stderr"},
		}, Action: runProtocolProxy},
		{Name: "exchange", Usage: "execute a bounded TCP/UDP protocol experiment and emit byte-backed results", Flags: []cli.Flag{
			&cli.StringFlag{Name: "spec", Required: true, Usage: "versioned JSON exchange specification (maximum 2 MiB)"},
		}, Action: runExchange},
		{Name: "collect-flows", Usage: "receive UDP flow exports into a fresh output directory", Flags: []cli.Flag{
			&cli.StringFlag{Name: "listen", Value: "127.0.0.1:2055", Usage: "local UDP address"},
			&cli.StringFlag{Name: "out", Required: true, Usage: "existing directory without flow-export artifacts"},
			&cli.DurationFlag{Name: "duration", Value: time.Minute, Usage: "bounded collection duration"},
		}, Action: runCollectFlows},
		{Name: "exported-flows", Usage: "rank one exporter/domain's normalized flow metadata", Flags: []cli.Flag{
			&cli.StringFlag{Name: "read", Required: true, Usage: "FlowExports.jsonl with finalized health sidecar"},
			&cli.StringFlag{Name: "exporter", Required: true, Usage: "transport exporter IP:port"},
			&cli.StringFlag{Name: "format", Required: true, Usage: "netflow-v5, netflow-v9, ipfix or sflow-v5"},
			&cli.StringFlag{Name: "domain", Required: true, Usage: "observation domain or engine/subagent identifier"},
			&cli.StringFlag{Name: "start-ns", Required: true, Usage: "inclusive UTC nanosecond start"},
			&cli.StringFlag{Name: "end-ns", Required: true, Usage: "inclusive UTC nanosecond end"},
			&cli.StringFlag{Name: "time-basis", Value: "flow", Usage: "flow or receive; sFlow provides receive time only"},
			&cli.StringFlag{Name: "host", Usage: "either endpoint IP or CIDR"},
			&cli.StringFlag{Name: "group-by", Value: "srcIP", Usage: "srcIP, dstIP, dstPort, protocol, ingress, egress, srcAS, dstAS or nextHop"},
			&cli.IntFlag{Name: "limit", Value: 100, Usage: "returned groups (1..1000)"},
			&cli.DurationFlag{Name: "timeout", Value: 2 * time.Minute},
		}, Action: runExportedFlows},
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

func runProtocolProxy(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 0 {
		return fmt.Errorf("protocol-proxy does not accept positional arguments")
	}
	var spec protocoltest.Proxy
	if err := readExperimentSpec(cmd.String("spec"), &spec); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", cmd.String("listen"))
	if err != nil {
		return err
	}
	defer listener.Close()
	if _, err := fmt.Fprintln(cmd.Root().ErrWriter, "Protocol proxy listening on", listener.Addr().String()); err != nil {
		return err
	}
	data, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	observations, runErr := protocoltest.ProxyOne(ctx, listener, spec)
	status, message := "completed", ""
	if runErr != nil {
		status = "error"
		message = runErr.Error()
	}
	result := struct {
		Version             int                             `json:"version"`
		ConfigurationSHA256 string                          `json:"configurationSHA256"`
		Status              string                          `json:"status"`
		Error               string                          `json:"error,omitempty"`
		Observations        []protocoltest.ProxyObservation `json:"observations"`
	}{1, hex.EncodeToString(digest[:]), status, message, observations}
	return errors.Join(runErr, json.NewEncoder(cmd.Root().Writer).Encode(result))
}

func runExchange(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 0 {
		return fmt.Errorf("exchange does not accept positional arguments")
	}
	var spec protocoltest.Exchange
	if err := readExperimentSpec(cmd.String("spec"), &spec); err != nil {
		return err
	}
	result, runErr := protocoltest.Run(ctx, spec)
	return errors.Join(runErr, json.NewEncoder(cmd.Root().Writer).Encode(result))
}

func readExperimentSpec(path string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 2<<20 {
		return fmt.Errorf("exchange specification exceeds 2 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("exchange specification has trailing data")
	}
	return nil
}

func runCollectFlows(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 0 || cmd.Duration("duration") <= 0 {
		return fmt.Errorf("positive duration and no positional arguments required")
	}
	addr, err := net.ResolveUDPAddr("udp", cmd.String("listen"))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	recorder, err := flowexport.NewRecorder(cmd.String("out"), flowexport.DefaultConfig())
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, cmd.Duration("duration"))
	defer cancel()
	receiveErr := flowexport.Receive(bounded, conn, recorder)
	if errors.Is(receiveErr, context.DeadlineExceeded) && ctx.Err() == nil {
		receiveErr = nil
	}
	return errors.Join(receiveErr, recorder.Close())
}

func runExportedFlows(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() != 0 {
		return fmt.Errorf("exported-flows does not accept positional arguments")
	}
	start, err := strconv.ParseInt(cmd.String("start-ns"), 10, 64)
	if err != nil {
		return err
	}
	end, err := strconv.ParseInt(cmd.String("end-ns"), 10, 64)
	if err != nil {
		return err
	}
	domain, err := strconv.ParseUint(cmd.String("domain"), 10, 32)
	if err != nil {
		return err
	}
	id := uint32(domain)
	if cmd.Duration("timeout") <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, cmd.Duration("timeout"))
	defer cancel()
	result, err := flowexport.ReadReport(ctx, cmd.String("read"), flowexport.Query{StartNs: start, EndNs: end, TimeBasis: cmd.String("time-basis"), Exporter: cmd.String("exporter"), Format: cmd.String("format"), Domain: &id, Host: cmd.String("host"), GroupBy: cmd.String("group-by"), Limit: cmd.Int("limit")})
	if err != nil {
		return err
	}
	return json.NewEncoder(cmd.Root().Writer).Encode(result)
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
