# Hosts and identity

`net triage` shows the `Hosts.json` report built from a capture: the hosts, accounts and directory names that appeared in the traffic.

```sh
net capture -read office-lan.pcap -out identity-audit -dpi=false
net triage -read identity-audit
net triage -read identity-audit -json
```

What you see depends on the decoders enabled and the protocols in the capture. A capture without ARP, DHCP, Kerberos, NTLM or LDAP traffic yields few facts.

## Read claims with their evidence

| Observation                | What it tells you                                                        |
| -------------------------- | ------------------------------------------------------------------------ |
| ARP/DHCP/NDP binding       | This address and MAC were paired at this time, in this capture           |
| DHCP hostname/vendor data  | What the client says about itself. It is not verified                    |
| Kerberos / NTLM            | Principals or accounts visible in the exchange. Check source and outcome |
| LDAP / SAMR / LSA          | Directory subjects and some RPC identity data                            |
| Conflicting bindings/names | Investigate them and keep both observations                              |

An account returned by a directory server belongs to the directory, not necessarily to that server. NTLM-looking bytes outside a recognised protocol exchange cannot be tied to a host. Encryption, missing RPC state and unsupported encodings can stop extraction.

## Investigation sequence

1. Select the host by IP address and capture, not by hostname alone.
2. Inspect the binding, name or account and the evidence behind it.
3. Compare timestamps with DHCP lease changes, NAT and interface or VLAN boundaries.
4. Pivot to [related records](evidence.md) with exact selectors.
5. Keep conflicting and incomplete observations in anything you export.

`Hosts.json` caps the number of host, account and directory observations. The report says when a cap was hit, and the list is then incomplete. The JSON output keeps provenance that the terminal table omits.

For aggregation by MAC address, see [device profiles](device-profiles.md). For approved baseline state, see [behavior](behavioral-monitoring.md). Neither replaces identity evidence.
