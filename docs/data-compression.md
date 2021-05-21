---
description: Save storage space
---

# Data Compression

To reduce the amount of disk space used for storing the audit records, netcap compresses them by default with **gzip**. Compressed files have the extension **.ncap.gz.**

For this purpose Netcap currently uses the following gzip implementation:

{% embed url="https://github.com/klauspost/pgzip" caption="" %}

This implementation will split the data into blocks that are compressed in parallel, which can be useful for compressing big amounts of data. The output is a standard gzip file.

The gzip decompression is modified so it decompresses ahead of the current reader. This means that reads will be non-blocking and CRC calculation also takes place in a separate goroutine.

This design implements input buffering to the compressor which has a nice performance effect: writes to the compressor only block if the compressor is already compressing the number of blocks specified. This reduces waiting time for the workers which they can instead use to decode packets.

To get any performance gains, you should at least be compressing more than 1 megabyte of data at the time.

You should at least have a block size of 100k and at least a number of blocks that match the number of cores you would like to utilize, but about twice the number of blocks would be the best.

The default configuration uses 1MB block size and 2x NumCPUs as the number of blocks.

Netcap only uses the parallel gzip implementation for reading and writing audit records, as only there the required amounts of data are reached to allow a speedup. For tasks where the data size can vary heavily, such as decompressing HTTP requests and responses, the standard library **compress/gzip** is used instead.

