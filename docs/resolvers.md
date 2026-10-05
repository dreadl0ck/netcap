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

Database files:

* _domain-whitelist.csv_
* _dbip-city-lite.mmdb_
* _dbip-asn-lite.mmdb_
* _GeoLite2-City.mmdb_
* _GeoLite2-ASN.mmdb_
* _ja3fingerprint.json_
* _macaddress.io-db.json_
* _service-names-port-numbers.csv_
* _ja3UserAgents.json_
* _ja3erDB.json_

## Configuration

By default, all resolvers are disabled. You need to use the **-reverse-dns**, **-local-dns**, **-macDB**, **-ja3DB**, **-serviceDB** and **-geoDB** to enable what you want to use, or configure it via environment variables or config file, as described in:

{% page-ref page="configuration.md" %}

## Quickstart

Run `net util -download-dbs` for the current community database archive,
including DB-IP Lite in layout 2. GeoLite2 and Nmap probes are user-installed.

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
community archives. See [provider and installation instructions](../internal/dbs/README.md#geolocation-providers).

## Vendor Identification

To identify the vendor for a given MAC address, the **macaddress.io** JSON database is used.

At the time of this writing it contains 39,041 tracked address blocks and 28,961 unique vendors.

{% embed url="https://macaddress.io/database-download" caption="MacAddress.io database" %}

## Service Identification

Resolving port numbers to service names is done according to the CSV mapping from IANA, which contains 6104 records for TCP and UDP services at the time of this writing:

{% embed url="https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv" caption="IANA service names and ports" %}

## TLS Fingerprints

To identify hosts that use TLS connections, the Ja3 fingerprint database from **Trisul** is used:

{% embed url="https://github.com/trisulnsm/trisul-scripts/blob/master/lua/frontend\_scripts/reassembly/ja3/prints/ja3fingerprint.json" caption="" %}

For more fingerprints, you can load other databases additionally. For example from **ja3erDB**:

{% embed url="https://ja3er.com/downloads.html" caption="Ja3er JSON database downloads" %}
