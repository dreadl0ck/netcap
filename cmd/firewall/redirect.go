package firewall

import (
	"context"
	"errors"
	"time"

	"github.com/dreadl0ck/netcap/internal/transparentfirewall"
	"github.com/urfave/cli/v3"
)

func redirectFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "namespace", Required: true},
		&cli.StringFlag{Name: "interface", Required: true},
		&cli.StringFlag{Name: "service-cidr", Required: true},
		&cli.IntFlag{Name: "service-port", Required: true},
		&cli.IntFlag{Name: "gateway-port", Required: true},
		&cli.StringFlag{Name: "protocol", Required: true},
		&cli.StringFlag{Name: "tls-mode", Required: true, Usage: "plaintext | terminated"},
		&cli.StringSliceFlag{Name: "management-peer"},
	}
}

func runRedirect(ctx context.Context, c *cli.Command) error {
	cleanup, err := transparentfirewall.Install(ctx, transparentfirewall.Config{
		NetworkNamespace: c.String("namespace"), IngressInterface: c.String("interface"),
		OriginalService: c.String("service-cidr"), OriginalPort: c.Int("service-port"), GatewayPort: c.Int("gateway-port"),
		Protocol: c.String("protocol"), TLSMode: c.String("tls-mode"), ManagementPeers: c.StringSlice("management-peer"),
	})
	if cleanup == nil {
		return err
	}
	if err == nil {
		<-ctx.Done()
	}
	// Cleanup is idempotent and independently bounded. Retry transient nft failures
	// while keeping the namespace/table ownership lock held.
	var cleanupErr error
	for attempt := 0; attempt < 3; attempt++ {
		cleanupErr = cleanup()
		if cleanupErr == nil {
			break
		}
		if attempt < 2 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return errors.Join(err, cleanupErr)
}
