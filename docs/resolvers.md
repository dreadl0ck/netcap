---
description: Lookup everything!
---

# Resolvers

## Motivation

Lots of information is not available on first sight, and we need to combine our data with knowledge from other data sources to make it easier to understand for humans.

Think of resolving ip addresses to geolocations, hardware addreses to manufacturers, domains to ip addresses and vice versa, or simply identifying the service name associated with a given port number. Or consider filtering ip addresses or domain names against a whitelist, to eliminate known legitimate traffic.

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

An optional local `domain-whitelist.csv` contains `rank,domain` rows for the
filtered transforms. The Alexa feed is retired and no whitelist is shipped.

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
