# Firewall Response Actions

Current source supplies an explicit [application firewall and scoped nftables
enforcer](APPLICATION_FIREWALL.md). The older `iptables_*` capture-rule actions
use a different internal manager: the public capture CLI does not attach it. Adding
`iptables_block` to a YAML rule alone does not enable blocking: the executor
returns `firewall manager not configured` without an attached manager.

## Overview

| Capability | Current boundary |
| --- | --- |
| Detection alerts | Available through the normal rules engine |
| `iptables_block`, `iptables_reject` | Require explicitly integrated Linux manager |
| `iptables_log`, `iptables_rate_limit` | Return `ErrUnsupportedResponseAction`; action failure is counted, no LOG/rate enforcement |
| Firewall manager | Internal Go package, not a public importable SDK |
| `net firewall serve` / `netcap-firewall serve` | Explicit inline HTTP enforcement; rootless, separate policy format |
| `capture -firewall-policy FILE` | Retrospective decoder evaluation; replay cannot contact an enforcer |
| Live capture bridge plus `-firewall-effects-config FILE` | Explicitly admitted, source-attributed future containment; cannot recall the triggering transaction |

## Choose a response path

| Goal | Operator path |
| --- | --- |
| Observe and notify | Capture rules, [scoped correlation](RULES_ENGINE.md#scoped-capture-time-rules), then [durable redacted webhook delivery](RULES_ENGINE.md#durable-webhook-delivery) |
| Prevent HTTP/message forwarding | [WAF quickstart](APPLICATION_FIREWALL.md#quickstart); origin must accept only the intended proxy path |
| Gate a supported non-HTTP protocol | [Protocol gateways](APPLICATION_FIREWALL.md#protocol-gateways-and-optional-enforcer); deny a write in the request phase |
| Gate packets in Linux | `netcap-firewall network`; existing named namespace and explicit protected scope required |
| Contain future traffic from a live observation | Capture audit bridge and scoped `enforcer`; qualify live source attribution and expiration; select `--dry-run` explicitly for lease previews |

This corrects the old guide's implication that ordinary CLI capture automatically
blocks matches. `internal/rules/engine.go` exposes `SetFirewallManager`, but the
capture command paths do not call it. The separate `--firewall-effects-config`
bridge does not change the legacy action-manager contract.

## Requirements

An application integrating `internal/firewall` within this module needs Linux,
iptables/ip6tables, suitable network-administration privileges and the intended
network namespace. Non-Linux implementations return an unsupported error.
Detecting packets on a SPAN sensor does not place that sensor in the forwarding
path of the observed hosts.

## Architecture

`Engine` evaluates a rule, generates an alert and dispatches configured actions.
An explicitly attached manager owns a custom chain (default `NETCAP`), active
block state, allowlist and expiration cleanup. Setup inserts jumps from INPUT,
FORWARD and OUTPUT in that namespace; this is a real policy change even before
the first block action.

## Configuration

The internal integration points are:

| File | Contract |
| --- | --- |
| `internal/firewall/config.go` | Manager defaults/configuration |
| `internal/firewall/manager.go` | Linux setup, block/unblock and cleanup |
| `internal/rules/engine.go` | Manager attachment and action dispatch |
| `internal/rules/rule.go` | Action configuration/validation |

Use `DryRun` for a manager integration test and inspect its actual initialization
requirements; it is not a documented `capture` CLI flag. Allowlist and expiration
behavior must be verified for the chosen policy and address family.

## Response Action Types

The following disabled rule illustrates action syntax for a custom integration:

```yaml
rules:
  - name: Lab TCP Policy Candidate
    description: Observe a destination port explicitly prohibited by lab policy
    type: TCP
    expression: DstPort == 9999 && SYN && !ACK
    severity: low
    enabled: false
    actions:
      - type: iptables_block
        config:
          target: source
          duration: 5m
```

`target` selects the matched record's source/destination address. `duration`
accepts supported duration strings; inspect the executor for numeric handling.
Missing/ambiguous endpoints are not permission to substitute another address.

## Rule Examples

Use [rules](RULES_ENGINE.md) and [network detections](network-detections.md) to
collect candidates first. SYN counts do not prove SSH authentication failures;
long DNS names do not establish tunneling; a port number does not establish
malware. Response policy needs validated evidence beyond those heuristics.

## Firewall Manager API

For development inside this module, inspect `NewManager`, `BlockIP`, `BlockCIDR`,
`UnblockIP`, `UnblockCIDR` and `Close`. Handle errors and close orderly. External
Go modules cannot directly import this repository's `internal/firewall` package.

## Safety Features

Allowlist checks, bounded-duration blocks and orderly cleanup are implementation
mechanisms, not an independent recovery guarantee. A crash can prevent cleanup;
an IPv6 initialization warning does not prove IPv6 enforcement is active.

## Monitoring & Statistics

Check action errors separately from alert creation. An `Alert.ncap.gz` entry
does not prove an action succeeded or traffic was blocked. Compare manager state
with the real ruleset in the intended namespace when qualifying an integration.

## Best Practices

Keep detection-only rules separate from enabled response policy, test on an
isolated Linux fixture, and verify expiration/unblock and failure paths before
relying on automation. Preserve administrative recovery access independently of
the policy being tested.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `firewall manager not configured` | Released CLI has no manager wiring; YAML does not create it |
| Unsupported platform | Linux-only implementation |
| Permission/chain errors | Capabilities, binary availability and network namespace |
| Alert but no block | Action error, allowlist, dry-run and manager attachment |
| No rate limit | `iptables_rate_limit` is unsupported; inspect the action error |
