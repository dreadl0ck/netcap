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

func Flags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{Name: "behavior", Usage: "enable passive behavioral learning and monitoring"},
		&cli.StringFlag{Name: "behavior-baseline", Usage: "explicit persistent baseline path (default: output/Behavior.json)"},
		&cli.StringFlag{Name: "behavior-sensor", Value: "local", Usage: "stable sensor identity for behavioral network scope"},
		&cli.StringSliceFlag{Name: "behavior-prefix", Usage: "configured local CIDR prefix; repeat for multiple networks"},
		&cli.DurationFlag{Name: "behavior-learning", Value: 7 * 24 * time.Hour, Usage: "minimum capture-time learning coverage before approval"},
		&cli.Uint64Flag{Name: "behavior-min-samples", Value: 100, Usage: "minimum ingress observations before baseline approval"},
		&cli.IntFlag{Name: "behavior-max-facts", Value: 10000, Usage: "maximum retained behavioral facts"},
	}
}

// Start returns a shutdown function that checkpoints and reports all failures.
func Start(command *cli.Command, coll *collector.Collector, output, iface string, live bool) (func() error, error) {
	if !command.Bool("behavior") && command.String("behavior-baseline") == "" {
		return func() error { return nil }, nil
	}
	if command.Uint64("behavior-min-samples") == 0 || command.Duration("behavior-learning") <= 0 || command.Int("behavior-max-facts") < 1 || command.Int("behavior-max-facts") > 100000 {
		return nil, errors.New("positive learning duration/sample count and fact limit 1..100000 are required")
	}
	path := command.String("behavior-baseline")
	if path == "" {
		path = filepath.Join(output, "Behavior.json")
	}
	sink, err := rules.NewFileAlertWriter(output)
	if err != nil {
		return nil, err
	}
	engine, err := behavior.Open(behavior.Config{Path: path, MinLearning: command.Duration("behavior-learning"), MinSamples: command.Uint64("behavior-min-samples"), MaxFacts: command.Int("behavior-max-facts")}, sink)
	if err != nil {
		return nil, errors.Join(err, sink.Close())
	}
	scope := behavior.Scope{Sensor: command.String("behavior-sensor"), Interface: iface}
	if !live {
		scope.Interface = "pcap"
	}
	if scope.Sensor == "" || scope.Interface == "" {
		return nil, errors.Join(errors.New("behavioral sensor/interface are required"), engine.Close(), sink.Close())
	}
	prefixes := command.StringSlice("behavior-prefix")
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
