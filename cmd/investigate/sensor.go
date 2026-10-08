package investigate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/dreadl0ck/netcap/internal/collector"
	"github.com/urfave/cli/v3"
)

func sensorCommands() []*cli.Command {
	commands := []*cli.Command{}
	for _, mode := range []string{"seal", "import", "prune"} {
		flags := []cli.Flag{&cli.StringFlag{Name: "out", Required: true, Usage: "private sensor store directory"}, &cli.StringFlag{Name: "sensor-id", Required: true, Usage: "authorized sensor identity"}, &cli.StringFlag{Name: "key-file", Required: true, Usage: "file containing at least 32 bytes of shared key material"}, &cli.DurationFlag{Name: "retention", Value: 24 * time.Hour, Usage: "maximum retention (at most 30 days)"}, &cli.Int64Flag{Name: "max-bytes", Value: 1 << 30, Usage: "maximum imported bundle bytes"}, &cli.DurationFlag{Name: "timeout", Value: 2 * time.Minute}}
		if mode != "prune" {
			flags = append(flags, &cli.StringFlag{Name: "read", Required: true, Usage: "collector output for seal, signed bundle for import"})
		}
		commands = append(commands, &cli.Command{Name: "sensor-" + mode, Usage: map[string]string{"seal": "seal completed collector output as a signed sensor bundle", "import": "verify and import a signed sensor bundle into its authorized namespace", "prune": "remove expired imports for the explicitly authorized sensor"}[mode], Flags: flags, Action: func(ctx context.Context, cmd *cli.Command) error { return runSensor(ctx, cmd, mode) }})
	}
	return commands
}

func runSensor(ctx context.Context, cmd *cli.Command, mode string) error {
	if cmd.Args().Len() != 0 || cmd.Duration("timeout") <= 0 {
		return fmt.Errorf("no positional arguments and positive timeout required")
	}
	file, err := os.Open(cmd.String("key-file"))
	if err != nil {
		return err
	}
	defer file.Close()
	key, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return err
	}
	if len(key) < 32 || len(key) > 4096 {
		return fmt.Errorf("sensor key must contain 32..4096 bytes")
	}
	ctx, cancel := context.WithTimeout(ctx, cmd.Duration("timeout"))
	defer cancel()
	now := time.Now()
	scope := collector.SensorImportScope{SensorKeys: map[string][]byte{cmd.String("sensor-id"): key}, Now: now, MaxBytes: cmd.Int64("max-bytes"), MaxRetention: cmd.Duration("retention")}
	var result any
	switch mode {
	case "seal":
		result, err = collector.SealSensorOutput(ctx, cmd.String("read"), cmd.String("out"), cmd.String("sensor-id"), now, now.Add(cmd.Duration("retention")), key)
	case "import":
		result, err = collector.ImportSensorOutput(ctx, cmd.String("read"), cmd.String("out"), scope)
	case "prune":
		result, err = collector.PruneSensorImports(ctx, cmd.String("out"), scope)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(cmd.Root().Writer).Encode(result)
}
