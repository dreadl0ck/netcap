// Package command supplies the capture and agent behavioral-monitoring flags.
package command

import (
	"errors"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/collector"
	"github.com/dreadl0ck/netcap/internal/rules"
)

type Options struct {
	Policy     *behavior.Policy
	Enabled    bool
	Baseline   string
	Sensor     string
	Prefixes   []string
	Learning   time.Duration
	MinSamples uint64
	MaxFacts   int
}

func ReadOptions(command *cli.Command) Options {
	options := Options{Enabled: command.Bool("behavior") || command.String("behavior-baseline") != "", Baseline: command.String("behavior-baseline"),
		Sensor: command.String("behavior-sensor"), Prefixes: command.StringSlice("behavior-prefix"), Learning: command.Duration("behavior-learning"),
		MinSamples: command.Uint64("behavior-min-samples"), MaxFacts: command.Int("behavior-max-facts")}
	if command.IsSet("behavior-window") || command.IsSet("behavior-fanout") || command.IsSet("behavior-rdp-attempts") || command.IsSet("behavior-approved-source") || command.IsSet("behavior-deny-country") || command.IsSet("behavior-deny-asn") {
		policy := behavior.DefaultPolicy()
		policy.WindowNS = int64(command.Duration("behavior-window"))
		policy.Fanout = command.Int("behavior-fanout")
		policy.RDPAttempts = command.Int("behavior-rdp-attempts")
		policy.ApprovedSources = command.StringSlice("behavior-approved-source")
		policy.DeniedCountries = command.StringSlice("behavior-deny-country")
		policy.DeniedASNs = command.StringSlice("behavior-deny-asn")
		options.Policy = &policy
	}
	return options
}

func Flags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{Name: "behavior", Usage: "enable passive behavioral learning and monitoring"},
		&cli.StringFlag{Name: "behavior-baseline", Usage: "explicit persistent baseline path (default: output/Behavior.json)"},
		&cli.StringFlag{Name: "behavior-sensor", Value: "local", Usage: "stable sensor identity for behavioral network scope"},
		&cli.StringSliceFlag{Name: "behavior-prefix", Usage: "configured local CIDR prefix; repeat for multiple networks"},
		&cli.DurationFlag{Name: "behavior-learning", Value: 7 * 24 * time.Hour, Usage: "minimum capture-time learning coverage before approval"},
		&cli.Uint64Flag{Name: "behavior-min-samples", Value: 100, Usage: "minimum ingress observations before baseline approval"},
		&cli.IntFlag{Name: "behavior-max-facts", Value: 10000, Usage: "maximum retained behavioral facts"},
		&cli.DurationFlag{Name: "behavior-window", Value: time.Minute, Usage: "capture-time window for lateral correlation"},
		&cli.IntFlag{Name: "behavior-fanout", Value: 5, Usage: "distinct internal SMB targets needed for a fan-out alert"},
		&cli.IntFlag{Name: "behavior-rdp-attempts", Value: 10, Usage: "independent internal RDP attempts needed for a pattern alert"},
		&cli.StringSliceFlag{Name: "behavior-approved-source", Usage: "approved scanner/jump-host IP or CIDR; repeat for multiple sources"},
		&cli.StringSliceFlag{Name: "behavior-deny-country", Usage: "destination country ISO code to flag by explicit policy; repeat for multiple codes"},
		&cli.StringSliceFlag{Name: "behavior-deny-asn", Usage: "destination ASN number to flag by explicit policy; repeat for multiple ASNs"},
	}
}

// Start returns a shutdown function that checkpoints and reports all failures.
func Start(command *cli.Command, coll *collector.Collector, output, iface string, live bool) (func() error, error) {
	return StartOptions(ReadOptions(command), coll, output, iface, live)
}

func StartOptions(options Options, coll *collector.Collector, output, iface string, live bool) (func() error, error) {
	if !options.Enabled {
		return func() error { return nil }, nil
	}
	if options.MinSamples == 0 || options.Learning <= 0 || options.MaxFacts < 1 || options.MaxFacts > 100000 {
		return nil, errors.New("positive learning duration/sample count and fact limit 1..100000 are required")
	}
	path := options.Baseline
	if path == "" {
		path = filepath.Join(output, "Behavior.json")
	}
	sink, err := rules.NewFileAlertWriter(output)
	if err != nil {
		return nil, err
	}
	engine, err := behavior.Open(behavior.Config{Path: path, MinLearning: options.Learning, MinSamples: options.MinSamples, MaxFacts: options.MaxFacts, Policy: options.Policy}, sink)
	if err != nil {
		return nil, errors.Join(err, sink.Close())
	}
	scope := behavior.Scope{Sensor: options.Sensor, Interface: iface}
	if !live {
		scope.Interface = "pcap"
	}
	if scope.Sensor == "" || scope.Interface == "" {
		return nil, errors.Join(errors.New("behavioral sensor/interface are required"), engine.Close(), sink.Close())
	}
	prefixes := append([]string(nil), options.Prefixes...)
	provenance := "configured"
	if live && len(prefixes) == 0 {
		if nic, err := net.InterfaceByName(iface); err == nil {
			if addresses, err := nic.Addrs(); err == nil {
				for _, addr := range addresses {
					prefixes = append(prefixes, addr.String())
				}
			}
		}
		provenance = "interface"
	}
	for _, prefix := range prefixes {
		if err := engine.AddPrefix(scope, prefix, provenance); err != nil {
			return nil, errors.Join(err, engine.Close(), sink.Close())
		}
	}
	coll.SetBehaviorEngine(engine, scope)
	stop, done := make(chan struct{}), make(chan struct{})
	var checkpointErr error
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := engine.Checkpoint(); err != nil {
					checkpointErr = err
					return
				}
			}
		}
	}()
	var once sync.Once
	var closeErr error
	return func() error {
		once.Do(func() {
			close(stop)
			<-done
			observerErr := coll.GetBehaviorError()
			coll.SetBehaviorEngine(nil, scope)
			closeErr = errors.Join(observerErr, checkpointErr, engine.Close(), sink.Close())
		})
		return closeErr
	}, nil
}
