---
description: Lookup everything!
---

# Resolvers

## Motivation

Lots of information is not available on first sight, and we need to combine our data with knowledge from other data sources to make it easier to understand for humans.

Think of resolving ip addresses to geolocations, hardware addreses to manufacturers, domains to ip addresses and vice versa, or simply identifying the service name associated with a given port number. Or think of filtering ip addresses or domain names against a whitelist, to eliminate known legitimate traffic.

The resolvers package provides primitives for such tasks, and if possible, caches results in memory for best performance.

## Design

External data sources are stored in a central directory on the system, which defaults to **/usr/local/etc/netcap/db** but can be overridden using the **NC\_DATABASE\_SOURCE** environment variable.

Database files:

* domain-whitelist.csv
* GeoLite2-City.mmdb
* GeoLite2-ASN.mmdb
* ja3fingerprint.json
* macaddress.io-db.json
* service-names-port-numbers.csv

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

TODO: example and configuration

## Geolocation

To determine the geolocation for a given host, the MaxMind GeoLite database is used. The lite database is freely available, but you have to register on their website to download it.

{% embed url="https://dev.maxmind.com/geoip/geoip2/geolite2/" caption="GeoLite2 MaxMind" %}

Geolocation lookups can provide the Country, City and ASN where an ip adress is registered.

## Vendor Identification

To identify the vendor for a given MAC address, the **macaddress.io** JSON database is used.

At the time of this writing it contains 39,041 tracked address blocks and 28,961 unique vendors.

{% embed url="https://macaddress.io/database-download" caption="MacAddress.io database" %}

## Service Identification

Resolving port numbers to service names is done according to the CSV mapping from IANA, which contains 6104 records for TCP and UDP services at the time of this writing:

{% embed url="https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv" caption="IANA service names and ports" %}

## TLS Fingerprints

To identfiy hosts that use TLS connections, the Ja3 fingerprint database from Trisul is used:

{% embed url="https://github.com/trisulnsm/trisul-scripts/blob/master/lua/frontend\_scripts/reassembly/ja3/prints/ja3fingerprint.json" caption="" %}

