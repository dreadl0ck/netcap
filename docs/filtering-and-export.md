---
description: Process Netcap audit records and extract the data you are interested in
---

# Filtering and Export

## Exporting Data with net dump

Netcap offers a simple interface to filter for specific fields and select only those of interest. Filtering and exporting specific fields can be performed with all available audit record types, over a uniform command-line interface. By default, output is generated as CSV with the field names added as first line. It is also possible to use a custom separator string. Fields are exported in the order they are named in the select statement. Sub structures of audit records \(for example IPv4Options from an IPv4 packet\), are converted to a human readable string representation. More examples for using this feature on the command-line can be found in the usage section.

![](.gitbook/assets/netcap-export%20%282%29.svg)

Netcap offers a simple command-line interface to select fields of interest from the gathered audit records.

## Examples

Show available header fields:

```text
$ net dump -read UDP.ncap.gz -fields
Timestamp,SrcPort,DstPort,Length,Checksum,PayloadEntropy,PayloadSize
```

Print all fields for the supplied audit record:

```text
$ net dump -read UDP.ncap.gz
1331904607.100000,53,42665,120,41265,4.863994469989251,112 
1331904607.100000,42665,53,53,1764,4.0625550894074385,45 
1331904607.290000,51190,53,39,22601,3.1861758166070766,31 
1331904607.290000,56434,53,39,37381,3.290856864924384,31 
1331904607.330000,137,137,58,64220,3.0267194361875682,50
...
```

Selecting fields will also define their order:

```text
$ net dump -read UDP.ncap.gz -select Length,SrcPort,DstPort,Timestamp 
Length,SrcPort,DstPort,Timestamp
145,49792,1900,1499254962.084372
145,49792,1900,1499254962.084377
145,49792,1900,1499254962.084378
145,49792,1900,1499254962.084379 
145,49792,1900,1499254962.084380 
...
```

Print selection in the supplied order and convert timestamps to UTC time:

```text
$ net dump -read UDP.ncap.gz -select Timestamp,SrcPort,DstPort,Length -utc
2012-03-16 13:30:07.1 +0000 UTC,53,42665,120
2012-03-16 13:30:07.1 +0000 UTC,42665,53,53
2012-03-16 13:30:07.29 +0000 UTC,51190,53,39
2012-03-16 13:30:07.29 +0000 UTC,56434,53,39
2012-03-16 13:30:07.33 +0000 UTC,137,137,58
...
```

To save the output into a new file, simply redirect the standard output:

```text
$ net dump -read UDP.ncap.gz -select Timestamp,SrcPort,DstPort,Length -utc > UDP.csv
```

