package firewall

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/networkfirewall"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/urfave/cli/v3"
)

func networkFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "policy", Required: true}, &cli.StringFlag{Name: "namespace", Required: true}, &cli.StringFlag{Name: "interface", Required: true},
		&cli.StringSliceFlag{Name: "protected-cidr", Required: true}, &cli.StringSliceFlag{Name: "management-destination"},
		&cli.StringFlag{Name: "hook", Required: true, Usage: "input | forward"}, &cli.UintFlag{Name: "queue", Value: 100}, &cli.UintFlag{Name: "max-queue-len", Value: 1024},
		&cli.DurationFlag{Name: "deadline", Value: 100 * time.Millisecond}, &cli.StringFlag{Name: "failure-verdict", Required: true, Usage: "allow | deny"},
		&cli.BoolFlag{Name: "bypass-without-listener"}, &cli.BoolFlag{Name: "fail-open-on-overflow"}, &cli.BoolFlag{Name: "inspect-tls"}, &cli.StringFlag{Name: "effects-config"},
		&cli.BoolFlag{Name: "validate-only", Usage: "validate scope and policy without opening NFQUEUE"},
		&cli.StringFlag{Name: "fleet-agent-config"},
		&cli.StringFlag{Name: "policy-state-config"},
		&cli.StringFlag{Name: "operations-listen", Usage: "optional literal loopback metrics/status listener"},
		&cli.StringFlag{Name: "ownership-nonce", Usage: "immutable appliance nonce; keeps fail-closed hooks on shutdown"},
		&cli.BoolFlag{Name: "recover-owned", Usage: "recover exact journaled hooks after lifetime-lock fencing"},
	}
}

type packetEvaluator struct{ evaluator *runtimeEvaluator }

func packetEvent(p networkfirewall.PacketEvent) policy.Event {
	e := policy.Event{Protocol: "network", Phase: "request", ClientIP: p.SrcIP, Network: policy.NetworkEvent{SrcIP: p.SrcIP, DstIP: p.DstIP, SrcPort: p.SrcPort, DstPort: p.DstPort, Transport: p.Transport, IPVersion: p.IPVersion, TCPFlags: p.TCPFlags, Direction: p.Direction}}
	if p.TLS != nil {
		e.TLS = policy.TLSEvent{ServerName: p.TLS.ServerName, ALPN: strings.Join(p.TLS.ALPN, ","), Encrypted: true}
	}
	return e
}
func (p packetEvaluator) EvaluatePacket(e networkfirewall.PacketEvent) (networkfirewall.Decision, error) {
	// Readiness is an enforcement denial, never a fail-open evaluation error.
	if p.evaluator.fleetUnready.Load() {
		return networkfirewall.Decision{Verdict: networkfirewall.Deny}, nil
	}
	d, err := p.evaluator.Evaluate(packetEvent(e))
	return networkfirewall.Decision{Verdict: networkfirewall.Verdict(d.Verdict)}, err
}
func networkConfig(c *cli.Command) (networkfirewall.Config, error) {
	if c.String("policy-state-config") != "" && (c.String("failure-verdict") != "deny" || c.Bool("bypass-without-listener") || c.Bool("fail-open-on-overflow")) {
		return networkfirewall.Config{}, errors.New("authoritative policy-state requires deny on NFQUEUE deadline, overflow and missing listener")
	}
	if c.Uint("queue") > 65535 || c.Uint("max-queue-len") > 65535 {
		return networkfirewall.Config{}, errors.New("queue and max-queue-len must fit uint16")
	}
	return networkfirewall.Config{Namespace: c.String("namespace"), Interface: c.String("interface"), ProtectedCIDRs: c.StringSlice("protected-cidr"), ManagementDestinations: c.StringSlice("management-destination"), Hook: c.String("hook"), Queue: uint16(c.Uint("queue")), MaxQueueLen: uint32(c.Uint("max-queue-len")), Deadline: c.Duration("deadline"), FailureVerdict: networkfirewall.Verdict(c.String("failure-verdict")), BypassWithoutListener: c.Bool("bypass-without-listener"), FailOpenOnOverflow: c.Bool("fail-open-on-overflow"), InspectTLS: c.Bool("inspect-tls")}, nil
}
func runNetwork(ctx context.Context, c *cli.Command) error {
	cfg, err := networkConfig(c)
	cfg.OwnershipNonce, cfg.RecoverOwned = c.String("ownership-nonce"), c.Bool("recover-owned")
	if err != nil {
		return err
	}
	r, err := newEvaluator(ctx, c, c.String("policy"))
	if err != nil {
		return err
	}
	defer r.Close()
	f, err := networkfirewall.New(cfg, packetEvaluator{r})
	if err != nil {
		return err
	}
	if c.Bool("validate-only") {
		if path := c.String("fleet-agent-config"); path != "" {
			_, closeTransport, err := agentConfig(path, r.broker != nil)
			closeTransport()
			return err
		}
		return nil
	}
	r.attachOperations(f.Operations)
	stop, err := startOperations(c.String("operations-listen"), f.Operations)
	if err != nil {
		return err
	}
	defer stop()
	return r.runWithAgent(ctx, c, f.Run)
}
