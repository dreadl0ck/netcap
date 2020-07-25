---
description: Identify applications and categories
---

# Deep Packet Inspection

## Libprotoident

NETCAP has support for using **libprotoident** \(v[2.0.14](https://github.com/wanduow/libprotoident/releases/tag/2.0.14-1)\), to identify 45 application categories and 500+ applications and protocols!

The full list of supported protocols can be found here:

{% embed url="https://github.com/wanduow/libprotoident/wiki/SupportedProtocols" caption="Libprotoident Supported Protocols" %}

**libprotoident** is maintained by the WAND group, you can download and install the library here:

{% embed url="https://github.com/wanduow/libprotoident" caption="Libprotoident Source Code" %}

## nDPI

Furthermore **nDPI** \(v3.0\) can be used to identify 244 applications, they are listed here:

{% embed url="https://github.com/ntop/nDPI/wiki/Supported-Protocols" caption="nDPI Supported Protocols" %}

**nDPI** is mainted by **ntop**, and can be downloaded here:

{% embed url="https://github.com/ntop/nDPI" caption="nDPI Source Code" %}

The results from all heuristic engines \(lPI, nDPI and go heuristics\) get dedpulicated automatically. Future versions could create a certainity score based on the number of votes from different heuristics.

DPI is currently used to indicate which applications have been seen for which **IPProfile**, when using the **DeviceProfile** decoder.

Read more about DeviceProfiles here:

{% page-ref page="device-profiles.md" %}

## Platform Support

NETCAPs DPI integration is currently only available on linux and macOS.

