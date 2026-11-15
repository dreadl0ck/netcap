package mcp

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/internal/distributed"
	"github.com/dreadl0ck/netcap/internal/policy"
)

type firewallSimulation struct {
	Bundle string         `json:"bundle"`
	Events []policy.Event `json:"events,omitempty"`
}
type distributedPlan struct {
	Role              string `json:"role" jsonschema:"enum=agent,enum=collector"`
	Certificate       string `json:"certificate"`
	Key               string `json:"key"`
	Address           string `json:"address"`
	ServerFingerprint string `json:"serverFingerprint,omitempty"`
	Interface         string `json:"interface,omitempty"`
	BPF               string `json:"bpf,omitempty"`
	Clients           string `json:"clients,omitempty"`
	OutputDirectory   string `json:"outputDirectory,omitempty"`
	MaxPendingBytes   int    `json:"maxPendingBytes,omitempty"`
	MaxFrameBytes     int    `json:"maxFrameBytes,omitempty"`
	MaxConnections    int    `json:"maxConnections,omitempty"`
}

func (s *Server) registerOperationTools() error {
	if err := localOperation(s, "evaluate_firewall_policy", "Parse/compile an actual firewall policy bundle and optionally replay up to 1000 synthetic events with isolated state and suppressed effects. Returns revision, normalized policy and decisions. No live target, listener, deployment or response action is changed; use the firewall's native scoped MCP for CAS/idempotent deployment.", false, func(ctx context.Context, r firewallSimulation) (any, error) {
		if len(r.Events) > 1000 {
			return nil, fmt.Errorf("at most 1000 synthetic events")
		}
		bundle, err := policy.Parse([]byte(r.Bundle))
		if err != nil {
			return nil, err
		}
		compiled, err := policy.CompileWithOptions(bundle, policy.CompileOptions{AllowEffects: true})
		if err != nil {
			return nil, err
		}
		decisions, err := compiled.Simulate(r.Events)
		return map[string]any{"revision": compiled.Revision(), "bundle": compiled.Bundle(), "decisions": decisions, "effects_dispatched": false, "scope": "offline simulation; no active firewall attachment"}, err
	}); err != nil {
		return err
	}
	return localOperation(s, "prepare_distributed_configuration", "Validate a real agent/collector identity and trust configuration and produce exact net CLI argv (never a shell command). Collector clients are validated using the core enrollment parser and persisted as an owned allowlist artifact. This prepares configuration, not a running daemon or proof of connectivity; identity private keys are never included in output.", false, func(ctx context.Context, r distributedPlan) (any, error) {
		if _, _, err := net.SplitHostPort(r.Address); err != nil {
			return nil, err
		}
		for _, path := range []string{r.Certificate, r.Key} {
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
				return nil, fmt.Errorf("identity certificate/key must be regular files at most 4 MiB")
			}
		}
		identity, err := distributed.LoadIdentity(r.Certificate, r.Key)
		if err != nil {
			return nil, err
		}
		fingerprint, err := distributed.IdentityFingerprint(identity)
		if err != nil {
			return nil, err
		}
		args := []string{r.Role, "-cert=" + r.Certificate, "-key=" + r.Key, "-addr=" + r.Address}
		out := map[string]any{"identity_fingerprint": fingerprint, "protocol_version": distributed.ProtocolVersion, "transport": "TLS 1.3 with pinned public keys; no TOFU"}
		switch r.Role {
		case "agent":
			pin, err := distributed.NormalizeFingerprint(r.ServerFingerprint)
			if err != nil {
				return nil, err
			}
			if r.Interface == "" || len(r.Interface) > 128 {
				return nil, fmt.Errorf("explicit capture interface required")
			}
			pending := r.MaxPendingBytes
			if pending == 0 {
				pending = 64 << 20
			}
			if pending < 1 || pending > 512<<20 {
				return nil, fmt.Errorf("maxPendingBytes must be 1..536870912")
			}
			args = append(args, "-server-fingerprint="+pin, "-iface="+r.Interface, "-bpf="+r.BPF, "-max-pending="+strconv.Itoa(pending))
			out["delivery_qualification"] = "unacknowledged memory queue; oldest batches drop beyond max-pending; collector ACK means written, not fsync"
		case "collector":
			allow, err := distributed.ParseAllowlist(strings.NewReader(r.Clients))
			if err != nil {
				return nil, err
			}
			if len(allow) > 256 {
				return nil, fmt.Errorf("at most 256 enrolled agents")
			}
			if !filepath.IsAbs(r.OutputDirectory) {
				return nil, fmt.Errorf("explicit absolute collector output directory required")
			}
			frame, connections := r.MaxFrameBytes, r.MaxConnections
			if frame == 0 {
				frame = distributed.DefaultMaxFrame
			}
			if connections == 0 {
				connections = 256
			}
			if frame < 1 || frame > 16<<20 || connections < 1 || connections > 256 {
				return nil, fmt.Errorf("invalid bounded collector frame/connection settings")
			}
			entry, _, err := s.carve.PutTyped("", "collector-clients", "validated enrollment configuration", "text/plain", []byte(r.Clients))
			if err != nil {
				return nil, err
			}
			if entry.Path == "" {
				return nil, fmt.Errorf("cannot persist owned enrollment file")
			}
			args = append(args, "-clients="+entry.Path, "-out="+r.OutputDirectory, "-max-frame="+strconv.Itoa(frame), "-max-conns="+strconv.Itoa(connections))
			out["enrolled_agents"], out["allowlist_artifact_id"] = len(allow), entry.ID
			out["configuration_lifetime"] = "owned allowlist is retained for at most one hour/32 artifacts; copy configuration to daemon-owned storage before deployment"
		default:
			return nil, fmt.Errorf("role must be agent or collector")
		}
		out["argv"] = args
		return out, nil
	})
}
