# Overview

The _Netcap_ \(NETwork CAPture\) framework efficiently converts a stream of network packets into highly accessible type-safe structured data that represent specific protocols or custom abstractions. These audit records can be stored on disk or exchanged over the network, and are well suited as a data source for machine learning algorithms. Since parsing of untrusted input can be dangerous and network data is potentially malicious, implementation was performed in a programming language that provides a garbage collected memory safe runtime.

It was developed for a series of experiments in my bachelor thesis: _Implementation and evaluation of secure and scalable anomaly-based network intrusion detection_. Currently, the thesis serves as documentation until the wiki is ready, it is included at the root of this repository \(file: [mied18.pdf](https://github.com/dreadl0ck/netcap/blob/master/mied18.pdf)\). Slides from my presentation at the Leibniz Supercomputing Centre of the Bavarian Academy of Sciences and Humanities are available on [researchgate](https://www.researchgate.net/project/Anomaly-based-Network-Security-Monitoring).

The project won the 2nd Place at Kaspersky Labs SecurIT Cup 2018 in Budapest.

_Netcap_ uses Google's Protocol Buffers to encode its output, which allows accessing it across a wide range of programming languages. Alternatively, output can be emitted as comma separated values, which is a common input format for data analysis tools and systems. The tool is extensible and provides multiple ways of adding support for new protocols, while implementing the parsing logic in a memory safe way. It provides high dimensional data about observed traffic and allows the researcher to focus on experimenting with novel approaches for detecting malicious behavior in network environments, instead of fiddling with data collection mechanisms and post processing steps. It has a concurrent design that makes use of multi-core architectures. The name _Netcap_ was chosen to be simple and descriptive. The command-line tool was designed with usability and readability in mind, and displays progress when processing packets. The latest version offers 58 audit record types of which 53 are protocol specific and 5 are flow models.

## Design Goals

* memory safety when parsing untrusted input
* ease of extension
* output format interoperable with many different programming languages
* concurrent design
* output with small storage footprint on disk
* maximum data availability
* allow implementation of custom abstractions
* rich platform and architecture support

### Framework Components

Currently there are 8 applications:

* net.capture \(capture audit records\)
* net.dump \(work with audit records\)
* net.label \(tool for creating labeled CSV datasets from netcap data\)
* net.collect \(collection server for distributed collection\)
* net.agent \(sensor agent for distributed collection\)
* net.proxy \(http reverse proxy for capturing traffic from web services\)
* net.util \(utility tool for validating audit records and converting timestamps\)
* net.export \(exporter for prometheus metrics\)



## Use Cases

* monitoring honeypots
* monitoring medical / industrial devices
* research on anomaly-based detection mechanisms
* Forensic data analysis



## License

Netcap is licensed under the GNU General Public License v3, which is a very permissive open source license, that allows others to do almost anything they want with the project, except to distribute closed source versions. This license type was chosen with Netcaps research purpose in mind, and in the hope that it leads to further improvements and new capabilities contributed by other researchers on the long term.

## Source Code Stats

generated with cloc version 1.80

> cloc --exclude-ext pb.go,py,rb cmd sensor server label types utils collector encoder netcap.go reader.go utils.go

```text
    175 text files.
    175 unique files.
    3 files ignored.

github.com/AlDanial/cloc v 1.80  T=0.12 s (1412.6 files/s, 130948.3 lines/s)
-------------------------------------------------------------------------------
Language                     files          blank        comment           code
-------------------------------------------------------------------------------
Go                             172           1963           3119          10862
-------------------------------------------------------------------------------
SUM:                           172           1963           3119          10862
```

