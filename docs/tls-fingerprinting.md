---
description: Identify client and server that are using encrypted connections
---

# TLS fingerprinting

## JA3

JA3 is a technique developed by Salesforce, to fingerprint the TLS client and server hellos.

The official python implementation can be found [here](https://github.com/salesforce/ja3). 

More details can be found in their blog post: 

{% embed url="https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41" caption="JA3 blog post from salesforce" %}

Support for JA3 and JA3S in netcap is implemented via:

{% embed url="https://github.com/dreadl0ck/ja3" caption="JA3\(S\) go package" %}



