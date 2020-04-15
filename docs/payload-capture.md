---
description: Capture full packet payloads
---

# Payload Capture

It is now possible to capture payload data for the following protocols: **TCP, UDP, ModbusTCP, USB**

This can be enabled with the **-payload** flag:

```text
$ net capture -read traffic.pcap -payload
```

Setting the flag works for both live and offlline capture, afterwards the raw payload bytes are stored in the **Payload** field of the audit records.

You can use the **-struc** flag with the **dump** tool to see the payload in the command-line:

```text
$ net dump -read TCP.ncap.gz -struc
```

