# Device profiles

A `DeviceProfile` summarises the traffic seen for one MAC address. `Host` and `Connection` records describe the addresses and conversations around it. A hostname or manufacturer shown in a profile comes from the traffic. It is not a verified asset inventory.

To profile the devices on a home or office network, capture its traffic and dump the profiles:

```sh
net capture -read home-network.pcap -out inventory-audit -dpi=false
net dump -read inventory-audit/DeviceProfile.ncap.gz -fields
net dump -read inventory-audit/DeviceProfile.ncap.gz -json
net triage -read inventory-audit -json
```

## Read the layers separately

| Evidence                  | What it tells you                                                            |
| ------------------------- | ---------------------------------------------------------------------------- |
| MAC / OUI                 | The link-layer address and the vendor assigned to its prefix                 |
| Device IPs                | Addresses seen with the device. NAT, relays and lease changes blur ownership |
| Contacts and counters     | A summary of peers and traffic, not the full history                         |
| Applications              | Classifier and decoder output available in this build                        |
| Hostname/account bindings | See `Hosts.json` for provenance and conflicts                                |
| Behavior baseline         | State you reviewed and approved, separate from the observed profile          |

What a profile contains depends on the link type and where you captured. Routed traffic shows the gateway's MAC for remote addresses, so don't assign all of those addresses to one physical device.

## Timing and limits

Profiles are written when the capture ends, so a running capture may not have every profile yet.

Contact lists are sampled: a profile keeps at most 4,096 contacts and 65,536 deduplication keys. Check `ContactObservations`, `ContactCountLowerBound` and `ContactsTruncated` instead of counting the displayed list.

Field definitions are in `types/netcap.proto`. Next, check [identity](host-identity.md) for names and accounts, or [behavior](behavioral-monitoring.md) for baselines.
