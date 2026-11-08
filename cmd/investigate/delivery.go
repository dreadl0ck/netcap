package investigate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dreadl0ck/netcap/internal/delivery"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/urfave/cli/v3"
)

func alertDeliveryCommand() *cli.Command {
	return &cli.Command{Name: "deliver-alerts", Usage: "enqueue saved alerts and attempt bounded, durable webhook delivery", Flags: []cli.Flag{
		&cli.StringFlag{Name: "read", Required: true, Usage: "capture output containing Alert.ncap.gz"},
		&cli.StringFlag{Name: "outbox", Required: true, Usage: "private persistent outbox directory; retain for retries/idempotency"},
		&cli.StringFlag{Name: "endpoint", Required: true, Usage: "HTTP(S) webhook URL without credentials or query"},
		&cli.StringFlag{Name: "scope", Required: true, Usage: "stable capture/source identity; reuse on retry"},
		&cli.IntFlag{Name: "limit", Value: 1000, Usage: "maximum audit records read and due notices attempted (1..10000)"},
		&cli.DurationFlag{Name: "timeout", Value: time.Minute, Usage: "maximum delivery run duration"},
	}, Action: runAlertDelivery}
}

func runAlertDelivery(ctx context.Context, cmd *cli.Command) error {
	limit := int(cmd.Int("limit"))
	if cmd.Args().Len() != 0 || limit < 1 || limit > delivery.MaxEntries || cmd.Duration("timeout") <= 0 || cmd.Duration("timeout") > 15*time.Minute {
		return fmt.Errorf("invalid delivery limits or positional arguments")
	}
	ctx, cancel := context.WithTimeout(ctx, cmd.Duration("timeout"))
	defer cancel()
	o, err := delivery.Open(cmd.String("outbox"), cmd.String("endpoint"))
	if err != nil {
		return err
	}
	defer o.Close()
	tail, err := rules.OpenAlertTail(filepath.Join(cmd.String("read"), "Alert.ncap.gz"), "")
	if err != nil {
		return err
	}
	defer tail.Close()
	for i := 0; ; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		event, err := tail.Next()
		if errors.Is(err, rules.ErrAlertNotReady) {
			break
		}
		if err != nil {
			return err
		}
		if i >= limit {
			return fmt.Errorf("alert input exceeds limit; increase -limit (already admitted notices remain durable)")
		}
		if _, err = o.Enqueue(cmd.String("scope"), event.Alert); err != nil {
			return err
		}
	}
	// Environment avoids exposing bearer tokens in command-line/process listings.
	err = o.Deliver(ctx, limit, os.Getenv("NETCAP_ALERT_WEBHOOK_TOKEN"))
	s, statusErr := o.Status()
	return errors.Join(err, statusErr, json.NewEncoder(cmd.Root().Writer).Encode(s), s.RequireDrained())
}
