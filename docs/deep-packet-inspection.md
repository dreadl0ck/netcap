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

Furthermore **nDPI** \(v4.14 Stable\) can be used to identify 244+ applications, they are listed here:

{% embed url="https://github.com/ntop/nDPI/wiki/Supported-Protocols" caption="nDPI Supported Protocols" %}

**nDPI** is mainted by **ntop**, and can be downloaded here:

{% embed url="https://github.com/ntop/nDPI" caption="nDPI Source Code" %}

The results from all heuristic engines \(lPI, nDPI and go heuristics\) get dedpulicated automatically. Future versions could create a certainity score based on the number of votes from different heuristics.

## Audit Records with Applications Field

DPI detected applications are stored in the **Applications** field, which is available in the following audit records:

- **Connection**: DPI applications detected for bidirectional flows
- **Service**: DPI applications detected for services running on specific IP:Port combinations
- **DeviceProfile**: Aggregated DPI applications seen from/to a specific MAC address
- **IPProfile**: Aggregated DPI applications seen from/to a specific IP address

The Applications field is a repeated string field (array) that contains the names of all detected applications for that audit record.

### DPI Classification Strategy

NETCAP invokes DPI classification for each packet up to `MaxPacketsPerFlow` (10 packets):

- **Invocation**: DPI is called for each of the first 10 packets per flow
- **Internal Management**: godpi internally checks `MinPacketsForClassification` (default: 1) before actually performing classification
- **Efficiency**: Results are cached after first successful classification
- **Performance**: Automatically stops after 10 packets per flow

This ensures short HTTP/REST API connections (typically 3-8 packets) are properly classified while maintaining performance on long-lived flows.

**Note:** The `ApplicationProto` field in Connection records may show "Payload" for HTTP connections. This is expected because gopacket does not decode HTTP at the individual packet level (only at the TCP stream reassembly level). The DPI `Applications` field contains the actual protocol identification.

Read more about DeviceProfiles here:

{% page-ref page="device-profiles.md" %}

## Platform Support

NETCAPs DPI integration is currently only available on linux and macOS.

