---
description: Look behind the curtain
---

# Troubleshooting

## First Aid

* are all files in place?
* does the current user have sufficient rights to access them?
* does the current user have sufficient rights to access the current working directory?

## Pitfalls

* the go flag package implementation only allows to set boolean value using the **-name=value** syntax \(e.g: **-debug=true**\), but strings can be set also using a space instead with the **-name value** syntax \(e.g: **-read traffic.pcap**\)

## Debug Mode

Use the **-debug** flag to generate debug logs. The files will be created in the directory from which the netcap process has been started. The reassembly engine logs data into **reassembly.log** and all other debug messages go into **debug.log.**

> Remember that netcap logs packet decoding errors into **errors.log!**

## Advanced Debugging

In order to use advanced debugging features, you will need to recompile the code and make a few changes. Some primitives in the core library have a second implementation that spawns an additional goroutine for each invocation to time out the call. This is useful to debug hangs in the reassembly or due to invocation of external code, for example the DPI integration of **nDPI** and **libprotoident**.

List of \*Timeout primitives:

* handlePacketTimeout\(p \*packet\) in collector.go
* AssembleWithContextTimeout\(...\) in tcpConnection.go
* GetProtocolsTimeout\(packet gopacket.Packet\) in dpi.go

Simply replace the calls to the original versions with the \*Timeout primitives, and if one of those will block for longer than the configured thresholds, the call will be interrupted and an error logged.

## Race Detection Builds

To debug synchronization problems and data races you can compile a version with the **-race** flag set for the go compiler and see if the program crashes due to a race condition.

There is a command implemented for that in the build scripts:

```text
$ zeus install-race
```

