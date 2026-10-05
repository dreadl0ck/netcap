package command

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/collector"
)

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
