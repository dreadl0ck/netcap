# Firewall response actions

To block traffic, use the [application firewall and nftables enforcer](APPLICATION_FIREWALL.md). The `iptables_*` actions in capture rules do not work from `net capture`. A rule that uses `iptables_block` fails with `firewall manager not configured`.

## Choose a response path

| Goal                                                                     | Use                                                                                                                                                       |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Get an alert and notify someone                                          | Capture rules, [scoped correlation](RULES_ENGINE.md#scoped-capture-time-rules), then [durable webhook delivery](RULES_ENGINE.md#durable-webhook-delivery) |
| Stop HTTP requests or messages from reaching a backend                   | [WAF quickstart](APPLICATION_FIREWALL.md#quickstart). The origin must accept traffic only from the proxy.                                                 |
| Gate a non-HTTP protocol (DNS, Redis, Postgres, SMTP, Modbus and others) | [Protocol gateways](APPLICATION_FIREWALL.md#protocol-gateways-and-optional-enforcer). Deny writes in the request phase.                                   |
| Filter packets on a Linux router                                         | `netcap-firewall network`, which needs an existing named namespace and a protected scope                                                                  |
| Block a host that a live capture just saw                                | The capture audit bridge and the `enforcer`. Add `--dry-run` to preview leases.                                                                           |

Capture rules only detect and alert. `net capture -firewall-policy FILE` evaluates a policy against decoded records, and a pcap replay never contacts an enforcer. A live capture with `-firewall-effects-config FILE` can block the offending host for a limited time. It cannot recall the request that triggered the block.

## Example: block a scanner for ten minutes

Web scanners probe paths such as `/.env`, which a normal visitor never requests. The policy below denies that request and asks the enforcer to block the client's source address for ten minutes:

```yaml
version: netcap-policy/v1
id: block-env-probes
mode: enforce
default: allow
rules:
  - id: deny-env-probe
    phase: request
    expression: 'Protocol == "http" && Path == "/.env"'
    action: deny
    status: 403
    effects:
      - {kind: block_source, target: client, duration: 10m, scope: lab-edge}
```

`scope` must name an entry under `scopes` in the effects config (`examples/firewall/effects-config.json`). That entry sets the enforcer endpoint, its token variable, the protected network and the traffic to block. A policy cannot set an endpoint. The shipped example blocks forward TCP/8080 traffic to `198.51.100.0/24` on interface `lab0` and protects `192.0.2.0/24`. A lease lasts at most 15 minutes.

## The iptables actions

The `iptables_*` actions only work in a Go program that embeds the firewall manager. They need Linux, iptables and ip6tables, network-administration privileges and the right network namespace. `net capture` has no such manager.

| Action                                | Status                                                     |
| ------------------------------------- | ---------------------------------------------------------- |
| `iptables_block`, `iptables_reject`   | Need the manager                                           |
| `iptables_log`, `iptables_rate_limit` | Not supported. They return `ErrUnsupportedResponseAction`. |

A rule for such a program looks like this. It blocks any host that sends a SYN to Telnet for 5 minutes:

```yaml
rules:
  - name: Telnet probe
    description: Source host sent a SYN to port 23, which nothing here serves
    type: TCP
    expression: DstPort == 23 && SYN && !ACK
    severity: medium
    enabled: false
    actions:
      - type: iptables_block
        config:
          target: source
          duration: 5m
```

`target` selects the source or destination address of the matched record. `duration` takes a duration string such as `5m`. If the record has no usable address, nothing is blocked.

The manager creates its own chain (default `NETCAP`) and inserts jumps from INPUT, FORWARD and OUTPUT into it. That changes the firewall policy of the namespace before the first block.

An alert in `Alert.ncap.gz` does not mean the action ran. Check for action errors, and compare the manager state with the real ruleset in the namespace. If the process crashes, cleanup can fail, so keep a way into the machine that does not depend on the policy you are testing.

## Troubleshooting

| Symptom                           | Check                                                             |
| --------------------------------- | ----------------------------------------------------------------- |
| `firewall manager not configured` | `net capture` has no manager. Use the enforcer or the WAF.        |
| Unsupported platform              | The manager only runs on Linux.                                   |
| Permission or chain errors        | Capabilities, the iptables binary and the network namespace       |
| Alert but no block                | Action error, allowlist, dry run, manager attached                |
| No rate limit                     | `iptables_rate_limit` is not supported. Look at the action error. |

To find candidates for a response rule, start with [rules](RULES_ENGINE.md) and [network detections](network-detections.md). A SYN count does not show failed SSH logins, so check what a rule really matches before it can block anything.
