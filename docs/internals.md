---
description: Framework inner workings and Implementation details
---

# Internals

## Packages

You can browse the source and sub packages on GoDev:

[https://pkg.go.dev/github.com/dreadl0ck/netcap?tab=subdirectories](https://pkg.go.dev/github.com/dreadl0ck/netcap?tab=subdirectories)

### cmd

The cmd package contains the command-line application. It receives configuration parameters from command-line flags, creates and configures a collector instance, and then starts collecting data from the desired source.

#### label

[https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.5/l](https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.4.7/collector)abel

The label package contains the code for creating labeled datasets. For now, the suricata IDS / IPS engine is used to scan the input PCAP and generate alerts. In the future, support could also be added for using YARA. Alerts are then parsed with regular expressions and transformed into the **label.SuricataAlert** type. This could also be replaced by parsing suricatas eve.json event logs in upcoming versions. A suricata alert contains the following information:

```go
// SuricataAlert is a summary structure of an alerts contents
type SuricataAlert struct {
    Timestamp   string
    Proto          string
    SrcIP          string
    SrcPort        int
    DstIP          string
    DstPort        int
    Classification string
    Description    string
}
```

In the next iteration, the gathered alerts are mapped onto the collected data. For layer types which are not handled separately, this is currently by using solely the timestamp of the packet, since this is the only field required by Netcap, however multiple alerts might exist for the same timestamp. To detect this and throw an error, the **-strict** flag can be used. The default is to ignore duplicate alerts for the same timestamp, use the first encountered label and ignore the rest. Another option is to collect all labels that match the timestamp, and append them to the final label with the **-collect** flag. To allow filtering out classifications that shall be excluded, the **-excluded** flag can be used. Alerts matching the excluded classi- fication will then be ignored when collecting the generated alerts. Flow, Connection, HTTP and TLS records mapping logic also takes source and destination information into consider- ation. The created output files follow the naming convention: **&lt;NetcapType&gt;\_labeled.csv**.

### types

[https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.5/t](https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.4.7/collector)ypes

The types package contains types.AuditRecord interface implementations for each supported protocol, to enable converting data to the CSV format. For this purpose, each protocol must provide a CSVRecord\(\) \[\]string and a CSVHeader\(\) \[\]string function. Additionally, a NetcapTimestamp\(\) string function that returns the Netcap timestamp must be implemented.

### decoder

[https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.5/e](https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.4.7/collector)ncoder

The decoder package implements conversion of decoded network protocols to protocol buffers. This has to be defined for each supported protocol. Two types of decoders exist: The LayerEncoder and the CustomEncoder.

#### GoPacket Decoder

A GoPacketDecoder operates on a gopacket.Layer and has to provide the gopacket.LayerType constant, as well a handler function to receive the layer and the timestamp and convert it into a protocol buffer.

#### Custom Decoder

A CustomDecoder operates on a gopacket.Packet and is used to decode traffic into abstractions such as Flows or Connections. To create it a name has to be supplied among three different handler functions to control initialization, decoding and deinitialization. Its handler function receives a gopacket.Packet interface type and returns a proto.Message. The postinit function is called after the initial initialization has taken place, the deinit function is used to teardown any additionally created structures for a clean exit. Both functions are optional and can be omitted by supplying nil as value.

### resolvers

[https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.5/resolvers](https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.4.7/resolvers)

Resolvers for lookup of various external information, such as geolocation, domain names, hardware addresses, port numbers etc

### dpi

[https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.5/dpi](https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.4.7/dpi)

Deep Packet Inspection integration, using a fork of **mushorg/go-dpi** that was extended to identify the full range of protocols offered by **nDPI** and **libprotoident**. Both libraries are loaded dynamically at runtime and is invoked via C bindings.

The fork can be found here:

{% embed url="https://github.com/dreadl0ck/go-dpi" caption="Deep Packet Inspection Package" %}

### delimited

[https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.5/delimited](https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.4.7/delimited)

Primitives for reading and writing length delimited binary data

### utils

[https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.5/utils](https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.4.7/utils)

The utils package contains shared utility functions used by several other packages.

### collector

[https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.5/collector](https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.4.7/collector)

The collector package provides an interface for fetching packets from a data source, this can either be a PCAP / PCAPNG file or directly from a named network interface. It is used to implement the command-line interface for Netcap.

{% hint style="info" %}
Warning: Do not use multiple instances of a collector in parallel! This is not supported yet. Once it is possible, this warning will be removed.
{% endhint %}

### io

[https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.5/io](https://pkg.go.dev/github.com/dreadl0ck/netcap@v0.4.7/io)

Primitives for atomic maps and write operations

## Caveats

Protocol buffers have a few caveats that developers and researchers should be aware of. First, there are no types for 16 bit signed \(int16\) and unsigned \(uint16\) integers in protobuf, also there is no type for unsigned 8 bit integers \(uint8\). This data type is seen a lot in network protocols, so the question arises how to represent it in protocol buffers. The non-fixed integer types use variable length encoding, so int32 is used instead. The variable-length encoding will take care of not sending the bytes that are not being used. Unfortunately, the mu type is too short for this purpose. Second, protocol buffers require all strings to be encoded as valid UTF-8, otherwise encoding to proto will fail. This means all input data that will be encoded as a string in protobuf must be checked to contain valid UTF-8, or they will create an error upon serialization and end up in the errors.pcap file. If this behavior is not desired strings must be filtered prior to setting them on the protocol buffer instances. Another thing that has to be kept in mind is that Netcap processes packets in parallel, thus the order in which packets are written to the dump file is not guaranteed. In experiments, no mixup was detected, and records were tracked in the correct order. However, under heavy load conditions or with a high number of workers, this might be different. Because of this caveat, the Netcap specification requires each record to preserve the timestamp, in order to allow sorting the packets afterwards, if required.

## Data Race Detection Builds

In concurrent programming, shared resources need to be synchronized, in order to guarantee their state when modifying or reading them. If access is not synchronized, race conditions occur, which will lead to faulty program behavior. To avoid this and detect race conditions early in the development cycle, the go toolchain offers compiling the program with the race detector enabled. This will let the application crash with stack traces to assist the developer in debugging, if a data race occurs. Programs with active race detection are slower by the factor of 10 to 100. To compile a Go program with the race detection enabled the **-race** flag must be added to the compilation command.

To compile a netcap binary with the race detection enabled use:

```text
$ zeus install-race
```

