package mcp

import (
	"fmt"
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
		&cli.Int64Flag{Name: "max-retained-tcp-mb", Value: 64, Usage: "Copied TCP reader payload budget across workers in MiB (1..1024)"},
		&cli.Int64Flag{Name: "max-retained-reassembly-mb", Value: 256, Usage: "Aggregate reassembly payload budget in MiB (1..4096)"},
		&cli.Int64Flag{Name: "max-retained-tcp-state-mb", Value: 64, Usage: "TCP parser-state budget in MiB (1..1024)"},
		&cli.Int64Flag{Name: "max-aggregate-state-mb", Value: 32, Usage: "Aggregate connection/flow state budget in MiB (1..1024)"},
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
	for name, max := range map[string]int64{"packet-segment-mb": 1024, "packet-retention-mb": 16384, "max-retained-tcp-mb": 1024, "max-retained-reassembly-mb": 4096, "max-retained-tcp-state-mb": 1024, "max-aggregate-state-mb": 1024} {
		if value := c.Int64(name); value < 1 || value > max {
			return nil, fmt.Errorf("--%s must be 1..%d MiB", name, max)
		}
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
		MaxRetainedTCPBytes: c.Int64("max-retained-tcp-mb") << 20, MaxRetainedReassemblyBytes: c.Int64("max-retained-reassembly-mb") << 20,
		MaxRetainedTCPStateBytes: c.Int64("max-retained-tcp-state-mb") << 20, MaxAggregateStateBytes: c.Int64("max-aggregate-state-mb") << 20,
		IncrementalHTTP: c.Bool("incremental-http"), CaptureTimeIdleExpiry: c.Bool("capture-time-idle-expiry"),
		LiveMaintenanceInterval: time.Second, LiveFlushInterval: time.Second,
		FlowExports: c.Bool("flow-exports"), FlowExportPorts: c.String("flow-export-ports"),
		ModbusRTUEndpoints: c.String("modbus-rtu-endpoints"), DNP3PointMap: c.String("dnp3-point-map"),
	}, nil
}
