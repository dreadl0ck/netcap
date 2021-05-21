---
description: Lookup everything!
---

# Resolvers

## Motivation

Lots of information is not available on first sight, and we need to combine our data with knowledge from other data sources to make it easier to understand for humans.

Think of resolving ip addresses to geolocations, hardware addreses to manufacturers, domains to ip addresses and vice versa, or simply identifying the service name associated with a given port number. Or consider filtering ip addresses or domain names against a whitelist, to eliminate known legitimate traffic.

The resolvers package provides primitives for such tasks, and if possible, caches results in memory for better performance.

## Design

External data sources are stored in a central directory on the system, which defaults to **/usr/local/etc/netcap/db** but can be overridden using the **NC\_DATABASE\_SOURCE** environment variable.

Database files:

* _domain-whitelist.csv_
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

You can download a bundled version of all databases except for the MaxMind GeoLite, here:

{% file src=".gitbook/assets/resolver-dbs \(1\) \(2\).zip" %}

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

To filter known legitimate domains away, the alexa top 1 million can be used for example.

{% embed url="https://aws.amazon.com/alexa-top-sites/" caption="" %}

You can download the CSV file here:

{% embed url="http://s3.amazonaws.com/alexa-static/top-1m.csv.zip" caption="" %}

Rename it to **domain-whitelist.csv** and move it into the database path:

```text
$ mv top-1m.csv /usr/local/etc/netcap/db/domain-whitelist.csv
```

## Geolocation

To determine the geolocation for a given host, the MaxMind GeoLite database is used. The lite database is freely available, but you have to register on their website to download it.

{% embed url="https://dev.maxmind.com/geoip/geoip2/geolite2/" caption="GeoLite2 MaxMind" %}

Geolocation lookups can provide the Country, City and ASN where an ip adress is registered.

Download the databases and move them into the database path.

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

