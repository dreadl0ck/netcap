package mcp

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/cmd/capture/webui"
	"github.com/dreadl0ck/netcap/defaults"
	behaviorcommand "github.com/dreadl0ck/netcap/internal/behavior/command"
	"github.com/urfave/cli/v3"
)

func captureFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{Name: "capture-evidence", Value: true, Usage: "Write capture identity, effective configuration and health evidence"},
		&cli.BoolFlag{Name: "retain-packets", Usage: "Retain bounded rotating PCAPNG packet evidence"},
		&cli.Int64Flag{Name: "packet-segment-mb", Value: 32, Usage: "Packet segment target in MiB (1..1024)"},
		&cli.Int64Flag{Name: "packet-retention-mb", Value: 512, Usage: "Packet disk budget in MiB (segment size..16384)"},
		&cli.Int64Flag{Name: "max-retained-tcp-mb", Usage: "Copied TCP reader payload budget across workers in MiB (0 = unlimited)"},
		&cli.Int64Flag{Name: "max-retained-reassembly-mb", Usage: "Shared reassembly page budget in MiB (0 = unlimited)"},
		&cli.Int64Flag{Name: "max-retained-tcp-state-mb", Usage: "TCP parser-state budget in MiB (0 = unlimited)"},
		&cli.Int64Flag{Name: "max-aggregate-state-mb", Value: defaults.MaxAggregateStateBytes >> 20, Usage: "Aggregate state budget in MiB (0 = memory-only)"},
		&cli.Int64Flag{Name: "max-retained-tcp-bytes", Value: defaults.MaxRetainedTCPBytes, Usage: "Copied TCP reader payload budget in bytes (0 = unlimited)"},
		&cli.Int64Flag{Name: "max-retained-reassembly-bytes", Value: defaults.MaxRetainedReassemblyBytes, Usage: "Shared reassembly page budget in bytes (0 = unlimited)"},
		&cli.Int64Flag{Name: "max-retained-tcp-state-bytes", Value: defaults.MaxRetainedTCPStateBytes, Usage: "TCP parser-state budget in bytes (0 = unlimited)"},
		&cli.Int64Flag{Name: "max-aggregate-state-bytes", Value: defaults.MaxAggregateStateBytes, Usage: "Aggregate state budget in bytes (0 = memory-only)"},
		&cli.BoolFlag{Name: "incremental-http", Usage: "Decode HTTP/1 with observed handshake incrementally within retained TCP bounds"},
		&cli.BoolFlag{Name: "capture-time-idle-expiry", Usage: "Expire idle observations by capture timestamps"},
		&cli.BoolFlag{Name: "flow-exports", Value: true, Usage: "Normalize observed NetFlow/IPFIX/sFlow exports"},
		&cli.StringFlag{Name: "flow-export-ports", Value: "2055,4739,6343,9995,9996", Usage: "Observed UDP destination ports for flow exports"},
		&cli.BoolFlag{Name: "network-detection", Value: true, Usage: "Enable capture-time network detections"},
		&cli.BoolFlag{Name: "dns-resolution-context", Usage: "Snapshot paired UDP DNS answers onto connections"},
		&cli.BoolFlag{Name: "evidence-links", Value: true, Usage: "Enable qualified related-evidence queries"},
		&cli.StringFlag{Name: "modbus-rtu-endpoints", Usage: "RTU-over-TCP destination allowlist (CSV IP:port or [IPv6]:port)"},
		&cli.StringFlag{Name: "dnp3-point-map", Usage: "Backend-local DNP3 CSV point-map path"},
	}
}

func captureRuntimeConfig(c *cli.Command) (*webui.RuntimeConfig, error) {
	bindingsFile, network := c.String("operator-bindings"), c.Bool("allow-fetch")
	for name, max := range map[string]int64{"packet-segment-mb": 1024, "packet-retention-mb": 16384} {
		if value := c.Int64(name); value < 1 || value > max {
			return nil, fmt.Errorf("--%s must be 1..%d MiB", name, max)
		}
	}
	budgets := make(map[string]int64)
	for _, name := range []string{"max-retained-tcp", "max-retained-reassembly", "max-retained-tcp-state", "max-aggregate-state"} {
		value, err := captureBudget(c, name)
		if err != nil {
			return nil, err
		}
		budgets[name] = value
	}
	if c.Int64("packet-segment-mb") > c.Int64("packet-retention-mb") {
		return nil, fmt.Errorf("packet retention must be at least one segment")
	}
	behavior := behaviorcommand.ReadOptions(c)
	if behavior.Enabled && (behavior.Learning <= 0 || behavior.MinSamples == 0 || behavior.MaxFacts < 1 || behavior.MaxFacts > 100000) {
		return nil, fmt.Errorf("behavior requires positive learning/sample bounds and max-facts 1..100000")
	}
	return &webui.RuntimeConfig{
		OperatorBindingsFile: &bindingsFile, OperatorNetwork: &network,
		Behavior: &behavior,
		Features: map[string]bool{"network-detection": c.Bool("network-detection"), "dns-resolution-context": c.Bool("dns-resolution-context"), "evidence-links": c.Bool("evidence-links")},
		Compress: true, Buffer: true, Proto: true, Context: true, MacDB: true, ServiceDB: true,
		Workers: defaults.CaptureWorkers(), PacketBuffer: defaults.PacketBuffer, MemBufSize: defaults.BufferSize,
		PromiscMode: true, SnapLen: defaults.SnapLen, BaseLayer: "ethernet", DecodeOptions: "default", ReassembleConnections: true,
		FlushEvery: defaults.FlushEvery, Checksum: defaults.Checksum, NoOptCheck: defaults.NoOptCheck, IgnoreFSMErr: defaults.IgnoreFSMErr, AllowMissingInit: defaults.AllowMissingInit,
		ClosePendingTimeout: defaults.ClosePendingTimeout, CloseInactiveTimeout: defaults.CloseInactiveTimeout,
		ConnFlushInterval: defaults.ConnFlushInterval, ConnTimeout: defaults.ConnTimeOut, FlowFlushInterval: defaults.FlowFlushInterval, FlowTimeout: defaults.FlowTimeOut,
		DefragIPv4: defaults.DefragIPv4, IgnoreUnknown: true,
		CaptureEvidence: c.Bool("capture-evidence"), RetainPackets: c.Bool("retain-packets"),
		PacketSegmentBytes: c.Int64("packet-segment-mb") << 20, PacketRetentionBytes: c.Int64("packet-retention-mb") << 20,
		MaxRetainedTCPBytes: budgets["max-retained-tcp"], MaxRetainedReassemblyBytes: budgets["max-retained-reassembly"],
		MaxRetainedTCPStateBytes: budgets["max-retained-tcp-state"], MaxAggregateStateBytes: budgets["max-aggregate-state"],
		IncrementalHTTP: c.Bool("incremental-http"), CaptureTimeIdleExpiry: c.Bool("capture-time-idle-expiry"),
		LiveMaintenanceInterval: time.Second, LiveFlushInterval: time.Second,
		FlowExports: c.Bool("flow-exports"), FlowExportPorts: c.String("flow-export-ports"),
		ModbusRTUEndpoints: c.String("modbus-rtu-endpoints"), DNP3PointMap: c.String("dnp3-point-map"),
	}, nil
}

func captureBudget(c *cli.Command, name string) (int64, error) {
	bytesFlag, mibFlag := name+"-bytes", name+"-mb"
	if c.IsSet(bytesFlag) && c.IsSet(mibFlag) {
		return 0, fmt.Errorf("--%s and --%s cannot be combined", bytesFlag, mibFlag)
	}
	value := c.Int64(bytesFlag)
	if c.IsSet(mibFlag) {
		mib := c.Int64(mibFlag)
		if mib < 0 || mib > (1<<63-1)>>20 {
			return 0, fmt.Errorf("--%s is outside the supported byte range", mibFlag)
		}
		value = mib << 20
	} else if !c.IsSet(bytesFlag) {
		key := "NC_" + strings.ToUpper(strings.ReplaceAll(bytesFlag, "-", "_"))
		if raw, ok := os.LookupEnv(key); ok {
			parsed, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("%s must be a nonnegative byte count: %w", key, err)
			}
			value = parsed
		}
	}
	if value < 0 {
		return 0, fmt.Errorf("--%s cannot be negative", bytesFlag)
	}
	return value, nil
}
