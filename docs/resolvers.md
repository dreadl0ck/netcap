---
description: Lookup everything!
---

# Resolvers

## Motivation

Lots of information is not available on first sight, and we need to combine our data with knowledge from other data sources to make it easier to understand for humans.

Think of resolving IP addresses to geolocations, hardware addresses to manufacturers, or identifying service names from port numbers. The filtered Maltego transforms can optionally suppress popular domains; popularity does not establish legitimacy or safety.

The resolvers package provides primitives for such tasks, and if possible, caches results in memory for better performance.

## Design

External data sources are stored in a central directory on the system, which defaults to **~/.config/netcap/dbs** but can be overridden using the **NC\_CONFIG\_ROOT** environment variable.

| Community file | Purpose |
| --- | --- |
| `netcap.sqlite` | NVD CVEs, structured CPE applicability and external reference links; SQLite schema 2 |
| `dbip-city-lite.mmdb`, `dbip-asn-lite.mmdb`, `geoip-sources.json` | DB-IP Lite location/ASN and source inventory |
| `service-names-port-numbers.csv` | IANA port names |
| `regexes.yaml` | UA-parser software/OS signatures |
| `hasshdb.json` | Pinned HASSH SSH software catalogue in signed releases |
| `netapi-top1m.csv` | NetAPI Top 1M popularity ranking (CC BY 4.0) |
| `RELEASE_MANIFEST.json`, `DATABASE_NOTICES.txt` | Exact file/source inventory and full applicable notices |

## Configuration

Use `net capture -h` for current defaults and the `-reverse-dns`, `-local-dns`,
`-macDB`, `-serviceDB` and `-geoDB` options. `-ja3DB` is retired. Configuration
and environment overrides are described in:

{% page-ref page="configuration.md" %}

## Quickstart

Run `net util -download-dbs`; repeat with `net util -update-dbs` to refresh.
Signed-release clients verify the embedded publisher root, signing certificate,
expiry, monotonic release sequence and exact archive/source hashes. Explicit
operator registries remain available for private publishers.

Netcap v0.14.0 uses the frozen `/dbs/v3/` compatibility snapshot. New signed
clients use `/dbs/signed/v1/`. Legacy v1/v2 distribution returns HTTP 410.

## DNS

Reverse DNS lookups can be used to identify the domains associated with an address. By default the standard system resolver will be contacted for this.

### Passive / Local DNS

Passive DNS will read the hosts mapping from a file and load it into memory, instead of looking up encountered adresses by contacting a resolver. This can be used to provide names for known hosts in your network for example.

To avoid producing lookups that leave the network, you can generate a hosts mapping based on the DNS traffic in your dumpfile using tshark:

```text
$ tshark -r traffic.pcap -q -z hosts
```

And provide it to netcaps resolver via a **hosts** file in the database directory.

## Domain Whitelisting

The 3 filtered Maltego transforms use **managed NetAPI Top 1M by default** from
`dbs/netapi-top1m.csv`, acquired by the database publisher and included in new
signed database releases. Update databases before using these defaults. The
retired Alexa `dbs/domain-whitelist.csv` remains inert.

Use `net transform --no-domain-popularity <transform> <Maltego arguments>` to
disable suppression. An unavailable or invalid selected list fails the transform;
initialization reuses the validated list instead of parsing it twice.

To override NetAPI, place an independently obtained CSV outside the managed database directory, for
example `~/.config/netcap/user-data/popularity.csv`. Pass its explicit path before
the transform name and the usual Maltego positional arguments:

```text
net transform --domain-popularity-list /absolute/path/popularity.csv --domain-popularity-format rank-domain toHTTPHostsFiltered <Maltego arguments>
```

| `--domain-popularity-format` | Required CSV shape |
| --- | --- |
| `rank-domain` (default; Tranco-style) | 2 columns: positive integer rank, registrable domain; no header |
| `netapi` | 2 columns; exact `NetAPI_Rank,Domain` header |
| `majestic` | 12 columns; exact `GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs` header; uses GlobalRank and Domain |

The 3 filtered transforms (`toHTTPHostsFiltered`, `toIncomingConnsFiltered`,
`toOutgoingConnsFiltered`) use the same membership rules as their byte-count
helpers. Parsing accepts quoted CSV and CRLF, normalizes case, a final DNS dot
and IDNA, and rejects IPs, unknown/public suffixes, malformed names, subdomain-only
list entries and duplicate ranks. Duplicate normalized domains are counted once.
ICANN and PRIVATE Public Suffix List rules, including wildcards and exceptions,
keep `alice.github.io` separate from `bob.github.io`; matching never takes just
the last 2 labels. HTTP Host matching also accepts a numeric port in 1–65535.

Limits are 128 MiB and 1,000,000 data rows. An explicit invalid/missing file fails
CLI preflight. Counts (`rows`, `loaded`, `duplicates`, `invalid`, `skipped`) are reported;
failed loads publish no partial suppression data. Core database replacement never
writes the external file. Paths inside `dbs`, including resolved symlinks, are
rejected for overrides. The managed importer skips syntactically valid entries
that are PSL roots, use unknown/retired suffixes or are not registrable domains;
external overrides remain strict. Skipping prevents a shared suffix from
suppressing every tenant beneath it. The distributed CSV is unchanged.

Rust provides the equivalent `netcap_resolvers::popularity::{Config,List}` API
and resolver-runtime configuration. Its capture CLI accepts
`--domain-popularity-list` and `--domain-popularity-format` (also YAML keys),
loads and reports the optional list, but does not suppress capture records.
Rust has no filtered Maltego transforms; this is not transform parity. Its help
and successful-load diagnostic explicitly say `no suppression of capture records`.

NetAPI / CodeRockers LTD publishes the [Top 1M](https://netapi.com/top-1-mln-websites/)
under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
[ToS §4.3](https://netapi.com/tos/#open-data), effective 2026-11-07, expressly
overrides §4.2's redistribution restrictions for this CSV. Slava clarified the
Majestic Million (CC BY 3.0) and Chrome UX Report (CC BY 4.0) inputs and confirmed
bundling/mirroring in [issue #102](https://github.com/dreadl0ck/netcap/issues/102#issuecomment-6711862258).
The publisher policy and archive notices retain attribution and the dataset link.

## Geolocation

`-geoProviders dbip,geolite2` uses bundled DB-IP Lite first and optional
user-installed GeoLite2 second. Use `dbip`, `geolite2` or `geolite2,dbip` to
control loading and priority; `NC_GEO_PROVIDERS` sets the same order.
Location and ASN fall back separately. The Databases page saves an order for new
captures and shows availability, loaded providers and build timestamps.
`-geoDB=false` disables enrichment.

DB-IP Lite (CC BY 4.0) is credited through the web UI footer and archive notices.
City names are approximate. User-installed MaxMind files are never included in
community archives. See [provider and installation instructions](https://github.com/dreadl0ck/netcap/blob/v0.15.2/internal/dbs/README.md#geolocation-providers).

## Vendor Identification

MAC vendor lookup uses the embedded OUI table. The macaddress.io download and
external catalogue reader are retired; `-macDB` does not fetch that service.

## Service Identification

Port names come from IANA's CSV mapping. They describe registered assignments,
not confirmation of the application actually using a port:

{% embed url="https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv" caption="IANA service names and ports" %}

## TLS Fingerprints

JA3/JA4 fingerprint calculation does not imply a catalogue lookup. The community
release ships no JA3 identification corpus; JA4+ remains an opt-in source build.
Legacy CMS and DHCP OS catalogue enrichment is disabled. Packet decoding and
built-in service-signature classification remain available without those files.
