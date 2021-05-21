---
description: This is where the magic happens
---

# Workers

## Introduction

To make use of multi-core processors, processing of packets should happen in an asynchronous way. Since Netcap should be usable on a stream of packets, fetching of packets has to happen sequentially, but decoding them can be parallelized. The packets read from the input data source \(PCAP file or network interface\) are assigned to a configurable number of workers routines via round-robin. Each of those worker routines operates independently, and has all selected decoders loaded. It decodes all desired layers of the packet, and writes the encoded data into a buffer that will be flushed to disk after reaching its capacity.

## Worker

[Workers](https://github.com/dreadl0ck/netcap/blob/master/collector/worker.go) are a core concept of _Netcap_, as they handle the actual task of decoding each packet. _Netcap_ can be configured to run with the desired amount of workers, the default is 1000, since this configuration has shown the best results on the development machine. Increasing the number of workers also increases the number of runtime operations for goroutine scheduling, thus performance might decrease with a huge amount of workers. It is recommended to experiment with different configurations on the target system, and choose the one that performs best. Packet data fetched from the input source is distributed to a worker pool for decoding in round robin style. Each worker decodes all layers of a packet and calls all available custom decoders. After decoding of each layer, the generated protocol buffer instance is written into the _Netcap_ data pipe. Packets that produced an error in the decoding phase or carry an unknown protocol are being written in the corresponding logs and dumpfiles.

> Note: by default the number of workers is set to the numbers of cores of your machine! You can use the **-workers** flag to overwrite this value.

![NETCAP worker](https://github.com/dreadl0ck/netcap/tree/767852a00d76fcf7c921a4f3830ae6cec0162481/docs/.gitbook/assets/netcap-worker%20%281%29.svg)

## Buffering

Each worker receives its data from an input channel. This channel can be buffered, by default the buffer size is 100, also because this configuration has shown the best results on the development machine. When the buffer size is set to zero, the operation of writing a packet into the channel blocks, until the goroutine behind it is ready for consumption. That means, the goroutine must finish the currently processed packet, until a new packet can be accepted. By configuring the buffer size for all routines to a specific number of packets, distributing packets among workers can continue even if a worker is not finished yet when new data arrives. New packets will be queued in the channel buffer, and writing in the channels will only block if the buffer is full.

![NETCAP buffered workers](.gitbook/assets/buffered-workers.svg)

## Data Pipe

The Netcap data pipe describes the way from a network packet that has been processed in a worker routine, to a serialized, delimited and compressed record into a file on disk.

![](.gitbook/assets/netcap-pipe.svg)

