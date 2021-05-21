---
description: Extract transferred files and save them to disk
---

# File Extraction

## Introduction

Various protocols allow transferring files \(e.g: HTTP, POP3\) and some are made for the sole purpose of transferring files \(FTP, SMB etc\).

From a network security monitoring perspective, transferred files are interesting because they can contain malicious software or prohibited content.

Netcap extracts files from HTTP and saves them to disk, for both HTTP responses and HTTP requests.

It uses the **File** audit record type to model the extracted information.

> Future versions will add file extraction support for other protocols as well.

## File Audit Records

The audit record definition for a file looks like this:

```erlang
message File {
    string        Timestamp   = 1;
    string        Name        = 2;
    int64         Length      = 3;
    string        Hash        = 4;
    string        Location    = 5;
    string        Ident       = 6;
    string        Source      = 7;
    string        ContentType = 8;
    PacketContext Context     = 9;
    string        Host        = 10;
    string        ContentTypeDetected = 11;
}
```

As can be seen, the content type indicated by the HTTP header is included, as well as the content type that was detected. In addition, the source of the File is specified \(e.g: from HTTP, Mail attachment etc\), as well the identifier of the connection where it originated from.

The Hash field currently holds an MD5 hash of the file, Location points to the path on disk where the file is stored.

> This will likely be replaced with a stronger hash function in the future.

## Usage

To enable file capture, set the **-fileStorage** flag and supply a path to store the files to \(will be created if it does not exist\):

```text
$ net capture -read traffic.pcap -fileStorage files
```

After capturing, lets inspect the directory contents:

```text
$ tree files
files
├── application
│   └── x-gzip
│       └── unknown-193.24.227.12->216.66.80.30-80->60075.gz
├── image
│   └── x-icon
│       └── favicon.ico-193.24.227.12->216.66.80.30-80->60076.ico
└── text
    └── html
        ├── unknown-193.24.227.12->216.66.80.30-80->55031.html
        ├── unknown-193.24.227.12->216.66.80.30-80->55032.html
        ├── unknown-193.24.227.12->216.66.80.30-80->55033.html
        └── unknown-80.237.133.136->192.168.110.10-80->1152.html

6 directories, 6 files
```

As you can see, files are sorted by their MIME types retrieved from classifying them using the go standard library and named after the TCP connection they originated from.

By default, only complete requests and responses are captured, if you also want to extract incomplete data, use the **-writeincomplete** flag:

```text
$ net capture -read traffic.pcap -fileStorage files -writeincomplete
```

Dumping a File on the commandline looks like this:

```text
$ net dump -read File.ncap.gz -struc
NC_File
Timestamp: "2015-03-08 14:05:29.664213 +0000 UTC"
Name: "ads.bmp"
Length: 126
Hash: "2d5a035011854b04a456b244b15a583b"
Location: "files/image/bmp/ads.bmp-80.239.178.178->192.168.0.51-80->41214.bmp"
Ident: "80.239.178.178->192.168.0.51-80->41214"
Source: "HTTP RESPONSE from /ads.bmp"
Context: <
  SrcIP: "192.168.0.51"
  DstIP: "80.239.178.178"
  SrcPort: "41214"
  DstPort: "80"
>
ContentTypeDetected: "image/bmp"
...
```

For properly exploring files for each host I recommend using the Maltego Integration:

{% page-ref page="maltego-integration.md" %}

![](.gitbook/assets/files.png)

