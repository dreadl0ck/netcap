# Hosts and identity

`net triage` presents the capture-derived `Hosts.json` report. It complements
packet and DeviceProfile records by distinguishing evidence about a host from
directory subjects mentioned in traffic.

```sh
net capture -read traffic.pcap -out identity-audit -dpi=false
net triage -read identity-audit
net triage -read identity-audit -json
```

The report depends on enabled decoders and visible traffic. A capture with no
identity-bearing protocols can legitimately have few facts.

## Read claims with their evidence

| Observation | Interpretation |
| --- | --- |
| ARP/DHCP/NDP binding | Address/MAC relationship in the observed scope/time |
| DHCP hostname/vendor data | A client-advertised claim, not authenticated identity |
| Kerberos / NTLM | Visible principals or account claims; retain source and outcome context |
| LDAP / SAMR / LSA | Directory subjects and selected RPC identity evidence |
| Conflicting bindings/names | Multiple observations to investigate, not a reason to discard contrary evidence |

An account returned by a directory server is not automatically an account on that
server. A raw NTLM-shaped byte sequence without a framed owning protocol is not
host attribution. Encryption, missing RPC state and unsupported encodings can
prevent extraction.

## Investigation sequence

1. Select the host by address and capture scope, not hostname alone.
2. Inspect the binding/name/account state and underlying evidence source.
3. Compare timestamps with DHCP lease changes, NAT and interface/VLAN boundaries.
4. Pivot to [related records](evidence.md) using exact selectors.
5. Preserve conflicting and incomplete observations in any exported conclusion.

`Hosts.json` schema 1 includes bounded host/account/directory observations and
overflow reporting. Overflow limits completeness. Full JSON retains provenance
that the compact terminal table cannot show. See [device profiles](device-profiles.md)
for MAC-centered aggregation and [behavior](behavioral-monitoring.md) for approved
baseline state; neither is interchangeable with identity evidence.
