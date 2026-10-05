package command

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/collector"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

func TestRemoteNotificationRunsAfterDurableLocalWrite(t *testing.T) {
	dir := t.TempDir()
	coll := &collector.Collector{}
	count := 0
	options := Options{Enabled: true, Sensor: "agent-fingerprint", Learning: time.Nanosecond, MinSamples: 2, MaxFacts: 100, OnAlert: func(alert *types.Alert) {
		reader, err := netio.Open(filepath.Join(dir, "Alert.ncap.gz"), 4096)
		if err != nil {
			t.Error("remote notification preceded local persistence", err)
			return
		}
		defer reader.Close()
		if _, err := reader.ReadHeader(); err != nil {
			t.Error(err)
			return
		}
		last := new(types.Alert)
		for {
			next := new(types.Alert)
			if err := reader.Next(next); err == io.EOF {
				break
			} else if err != nil {
				t.Error(err)
				return
			}
			last = next
		}
		if last.RuleName != alert.RuleName {
			t.Error("notified alert is not durable")
		}
		count++
	}}
	stop, err := StartOptions(options, coll, dir, "fixture", false)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	engine := coll.GetBehaviorEngine()
	scope := behavior.Scope{Sensor: options.Sensor, Interface: "pcap"}
	fact := behavior.Fact{Scope: scope, Kind: "edge", SrcIP: "192.0.2.1", DstIP: "192.0.2.2"}
	start := time.Unix(1700000000, 0)
	if err := engine.Observe(start, fact); err != nil {
		t.Fatal(err)
	}
	if err := engine.Observe(start.Add(time.Nanosecond), fact); err != nil {
		t.Fatal(err)
	}
	if err := engine.Change("approve", nil, "agent fixture"); err != nil {
		t.Fatal(err)
	}
	fact.DstIP = "192.0.2.3"
	if err := engine.Observe(start.Add(time.Second), fact); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("notifications = %d", count)
	}
	if _, err := json.Marshal(options); err != nil {
		t.Fatal("runtime options cannot serialize", err)
	}
}

func TestCommandStartsScopedObserverAndPersistsOnShutdown(t *testing.T) {
	dir := t.TempDir()
	coll := &collector.Collector{}
	command := &cli.Command{Flags: Flags(), Action: func(ctx context.Context, c *cli.Command) error {
		stop, err := Start(c, coll, dir, "unused-offline-interface", false)
		if err != nil {
			return err
		}
		defer stop()
		engine := coll.GetBehaviorEngine()
		if engine == nil {
			t.Fatal("observer not attached")
		}
		fact := behavior.Fact{Scope: behavior.Scope{Sensor: "fixture", Interface: "pcap"}, Kind: "device", MAC: "00:11:22:33:44:55"}
		if err := engine.Observe(time.Unix(1700000000, 0), fact); err != nil {
			return err
		}
		if err := stop(); err != nil {
			return err
		}
		if coll.GetBehaviorEngine() != nil {
			t.Fatal("observer still attached after shutdown")
		}
		return nil
	}}
	if err := command.Run(context.Background(), []string{"test", "-behavior", "-behavior-sensor", "fixture", "-behavior-prefix", "192.0.2.130/25"}); err != nil {
		t.Fatal(err)
	}
	state, err := behavior.ReadSnapshot(filepath.Join(dir, "Behavior.json"))
	if err != nil {
		t.Fatal(err)
	}
	if state.Samples != 1 || len(state.Observed) != 2 {
		t.Fatalf("snapshot = %+v", state)
	}
	for _, observation := range state.Observed {
		if observation.Fact.Kind == "prefix" && (observation.Fact.Value != "192.0.2.128/25" || observation.FirstSeen != 1700000000000000000) {
			t.Fatal("prefix used wall time or guessed mask")
		}
	}
}

func TestCommandRejectsInvalidLimits(t *testing.T) {
	for _, args := range [][]string{
		{"-behavior", "-behavior-learning", "0s"},
		{"-behavior", "-behavior-min-samples", "0"},
		{"-behavior", "-behavior-max-facts", "0"},
	} {
		dir := t.TempDir()
		command := &cli.Command{Flags: Flags(), Action: func(ctx context.Context, c *cli.Command) error {
			_, err := Start(c, &collector.Collector{}, dir, "en0", false)
			return err
		}}
		if err := command.Run(context.Background(), append([]string{"test"}, args...)); err == nil {
			t.Fatalf("accepted invalid flags %v", args)
		}
	}
}
