# USB capture

Netcap decodes USB traffic from PCAP files that use a supported USB link type. The USB header layout differs between operating systems, so capture with a tool and platform that you have confirmed works.

## Read a USB capture file

```sh
net capture -read usb.pcap -out usb-audit -base usb -payload -dpi=false
net dump -read usb-audit/USB.ncap.gz -fields
net dump -read usb-audit/USB.ncap.gz -json
```

Compare the record count and payload fields with what you see in the original capture. Use `-payload` to keep the payload bytes that the capture contains.

## Live capture

Which USB interfaces exist depends on your OS, driver, permissions and capture tool. List what Netcap can see with `net util -interfaces`. Recent macOS versions do not expose an `XHC20` interface. If Netcap's live driver can't capture USB in a format it can decode, capture to a file with another tool and read that file.

## Audit records

| Record                 | Contents                                                                       |
| ---------------------- | ------------------------------------------------------------------------------ |
| `USB`                  | Transfer or event metadata, bus, device, endpoint, status, lengths and payload |
| `USBRequestBlockSetup` | Setup request type, request, value, index and length                           |

See `types/netcap.proto` or `dump -fields` for the current fields. Timestamps are integer nanoseconds. `-payload` cannot recover bytes that the capture tool did not record.
