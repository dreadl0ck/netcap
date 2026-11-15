package mcp

import (
	"context"
	"testing"

	"github.com/urfave/cli/v3"
)

func TestCaptureRuntimeConfig(t *testing.T) {
	command := &cli.Command{Flags: GetFlags(), Action: func(_ context.Context, c *cli.Command) error {
		rc, err := captureRuntimeConfig(c)
		if err != nil {
			return err
		}
		if !rc.RetainPackets || rc.PacketRetentionBytes != 128<<20 || rc.PacketSegmentBytes != 16<<20 || rc.MaxRetainedTCPBytes != 8<<20 || !rc.CaptureEvidence || !rc.FlowExports || !rc.Behavior.Enabled || rc.Behavior.MaxFacts != 500 || !rc.Features["dns-resolution-context"] {
			t.Fatalf("lost startup settings: %+v", rc)
		}
		if rc.OperatorBindingsFile == nil || *rc.OperatorBindingsFile != "/private/operator-bindings.json" || rc.OperatorNetwork == nil || !*rc.OperatorNetwork {
			t.Fatal("startup operator/network enrollment was not passed to backend")
		}
		return nil
	}}
	if err := command.Run(context.Background(), []string{"mcp", "--retain-packets", "--packet-retention-mb=128", "--packet-segment-mb=16", "--max-retained-tcp-mb=8", "--behavior", "--behavior-max-facts=500", "--dns-resolution-context", "--operator-bindings=/private/operator-bindings.json", "--allow-fetch"}); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureRuntimeRejectsInvalidBounds(t *testing.T) {
	for _, args := range [][]string{{"--packet-segment-mb=0"}, {"--packet-retention-mb=16385"}, {"--packet-segment-mb=64", "--packet-retention-mb=32"}, {"--max-retained-tcp-mb=-1"}, {"--behavior", "--behavior-max-facts=0"}} {
		command := &cli.Command{Flags: GetFlags(), Action: func(_ context.Context, c *cli.Command) error { _, err := captureRuntimeConfig(c); return err }}
		if err := command.Run(context.Background(), append([]string{"mcp"}, args...)); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}
