---
description: Resolve IP addresses, MAC addresses and ports to locations, vendors and names.
---

# Resolvers

Resolvers add context to the addresses in a capture: an IP address becomes a country and network, a MAC address becomes a manufacturer, a port becomes a service name. They read local databases and cache results in memory.

## Install the databases

```sh
net util -download-dbs
net util -update-dbs
```

The first command installs the databases, the second refreshes them. See [Database updates](database-updates.md) for details and troubleshooting.

The databases live in `~/.config/netcap/dbs`. Set `NC_CONFIG_ROOT` to use another directory.

| File                                                              | Purpose                                                           |
| ----------------------------------------------------------------- | ----------------------------------------------------------------- |
| `netcap.sqlite`                                                   | NVD CVEs, CPE applicability and reference links (SQLite schema 2) |
| `dbip-city-lite.mmdb`, `dbip-asn-lite.mmdb`, `geoip-sources.json` | DB-IP Lite location and ASN, and the source list                  |
| `service-names-port-numbers.csv`                                  | IANA port names                                                   |
| `regexes.yaml`                                                    | UA-parser software and OS signatures                              |
| `hasshdb.json`                                                    | HASSH SSH software catalogue                                      |
| `netapi-top1m.csv`                                                | NetAPI Top 1M domain popularity ranking (CC BY 4.0)               |
| `RELEASE_MANIFEST.json`, `DATABASE_NOTICES.txt`                   | File and source inventory, and the licence notices                |

## Configuration

Run `net capture -h` for the defaults of `-reverse-dns`, `-local-dns`, `-macDB`, `-serviceDB` and `-geoDB`. Config files and environment variables are described here:

{% content-ref url="configuration.md" %}
[configuration.md](configuration.md)
{% endcontent-ref %}

## Geolocation

Netcap resolves public IP addresses to a country, a city and an ASN. Use it to answer questions like "which countries and networks did this host talk to?":

```sh
net capture -read traffic.pcap -out geo-audit
net dump -read geo-audit/Connection.ncap.gz -csv \
  -filter 'SrcIP == "192.168.1.20"' \
  -select DstIP,DstGeoLocation,DstASN,Sni
```

Private addresses and addresses that cannot be resolved have empty location fields. `Host` records also carry a `Geolocation` field per address.

By default Netcap uses DB-IP Lite. `-geoProviders dbip,geolite2` also loads MaxMind GeoLite2 if you installed it yourself. The first provider in the list takes priority, and location and ASN fall back separately. Use `dbip`, `geolite2` or `geolite2,dbip` to pick the order. `NC_GEO_PROVIDERS` sets the same order. The Databases page of the web UI saves an order for new captures and shows which providers are loaded. `-geoDB=false` turns geolocation off.

DB-IP Lite (CC BY 4.0) is credited in the web UI footer and in the archive notices. City names are approximate. Netcap archives do not include MaxMind files because GeoLite2 needs your own MaxMind account and licence. See the [provider and installation instructions](https://github.com/dreadl0ck/netcap/blob/master/internal/dbs/README.md#geolocation-providers).

## DNS

Reverse DNS finds the domain names for an address. By default Netcap asks the system resolver (`-reverse-dns`).

### Local DNS

To avoid lookups that leave your network, give Netcap a hosts file instead (`-local-dns`). Netcap loads it into memory and uses it in place of a resolver. You can also use it to name the hosts on your own network.

You can generate the file from the DNS traffic in your capture with tshark:

```
$ tshark -r traffic.pcap -q -z hosts
```

Save the output as a file named `hosts` in the database directory.

## Domain popularity filter

The three filtered Maltego transforms (`toHTTPHostsFiltered`, `toIncomingConnsFiltered`, `toOutgoingConnsFiltered`) hide popular domains, so the graph shows the domains that are unusual for your traffic. They use the NetAPI Top 1M list in `dbs/netapi-top1m.csv`, which comes with the database downloads. Update the databases before you use the filter.

To see all domains, pass `--no-domain-popularity`:

```
net transform --no-domain-popularity <transform> <Maltego arguments>
```

If the selected list is missing or invalid, the transform fails.

### Use your own list

Place the CSV outside the `dbs` directory, for example `~/.config/netcap/user-data/popularity.csv`. Files inside `dbs`, including symlinks that resolve into it, are rejected. Pass the path before the transform name:

```
net transform --domain-popularity-list /absolute/path/popularity.csv --domain-popularity-format rank-domain toHTTPHostsFiltered <Maltego arguments>
```

| `--domain-popularity-format`          | CSV format                                                                                                                                                                                |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rank-domain` (default, Tranco style) | 2 columns: positive integer rank, registrable domain. No header.                                                                                                                          |
| `netapi`                              | 2 columns, with the header `NetAPI_Rank,Domain`                                                                                                                                           |
| `majestic`                            | 12 columns, with the header `GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs`. Netcap uses GlobalRank and Domain. |

The parser accepts quoted CSV and CRLF line endings. It normalises case, a trailing dot and IDNA names. It rejects IP addresses, unknown or public suffixes, malformed names, entries that are only a subdomain, and duplicate ranks. Duplicate domains after normalisation count once. Matching uses the Public Suffix List (ICANN and PRIVATE rules, including wildcards and exceptions), so `alice.github.io` and `bob.github.io` stay separate. An HTTP Host header may carry a port from 1 to 65535.

The limits are 128 MiB and 1,000,000 data rows. A missing or invalid file fails before the transform starts, and a failed load applies no partial list. Netcap reports the counts `rows`, `loaded`, `duplicates`, `invalid` and `skipped`. When it builds the managed list, Netcap skips public suffix roots, unknown suffixes and names that are not registrable domains, so one shared suffix cannot hide every site under it. Your own list is checked strictly instead.

The Rust capture CLI also accepts `--domain-popularity-list` and `--domain-popularity-format` (and the same YAML keys). It loads and reports the list but does not filter capture records, and there are no filtered Maltego transforms in Rust.

NetAPI / CodeRockers LTD publishes the [Top 1M](https://netapi.com/top-1-mln-websites/) under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Its [terms of service, section 4.3](https://netapi.com/tos/#open-data) allow redistribution of this CSV. The publisher also confirmed the Majestic Million (CC BY 3.0) and Chrome UX Report (CC BY 4.0) inputs and permission to bundle and mirror them in [issue #102](https://github.com/dreadl0ck/netcap/issues/102#issuecomment-6711862258). The archive notices keep the attribution and the dataset link.

## MAC vendors

Netcap looks up MAC address vendors in an OUI table built into the binary (`-macDB`). It does not call macaddress.io.

## Service names

Port names come from IANA's CSV list and tell you what a port is registered for. They do not tell you what runs on it. For that, see [Service identification and DPI](deep-packet-inspection.md).

{% embed url="https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv" %}

## TLS fingerprints

Netcap computes a fingerprint from each TLS client hello. It does not ship a list that maps fingerprints to software. See [TLS fingerprinting](tls-fingerprinting.md) for how to check them against a list of your own.
