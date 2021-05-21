---
description: A brief overview
---

# Overview

![](.gitbook/assets/screenshot-2019-05-05-at-13.41.40%20%282%29%20%282%29.png)

The _Netcap_ \(NETwork CAPture\) framework efficiently converts a stream of network packets into platform neutral type-safe structured audit records that represent specific protocols or custom abstractions. These audit records can be stored on disk or exchanged over the network, and are well suited as a data source for machine learning algorithms. Since parsing of untrusted input can be dangerous and network data is potentially malicious, implementation was performed in a programming language that provides a garbage collected memory safe runtime.

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

## Framework Components

Currently there are 8 applications:

* net.capture \(capture audit records live or from dumpfiles\)
* net.dump \(dump with audit records in various formats\)
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

## Demos

A simple demonstration of generating audit records from a PCAP dump file, querying and displaying the collected information in various ways

{% embed url="https://asciinema.org/a/217939" caption="" %}

And live operation decoding traffic from my wireless network interface, while I am surfing the web

{% embed url="https://asciinema.org/a/217941" caption="" %}

Watch a quick demo of the deep neural network for classification of malicious behavior, on a small PCAP dump file with traffic from the LOKI Bot. First, the PCAP file is parsed with [netcap](https://github.com/dreadl0ck/netcap-tf-dnn/blob/master/github.com/dreadl0ck/netcap), in order to get audit records that will be labeled afterwards with the [netlabel](https://github.com/dreadl0ck/netcap#netlabel-command-line-tool) tool. The labeled CSV data for the TCP audit record type is then used for training \(75%\) and evaluation \(25%\) of the classification accuracy provided by the deep neural network.

{% embed url="https://asciinema.org/a/217944" caption="" %}

## License

Netcap is licensed under the GNU General Public License v3, which is a very permissive open source license, that allows others to do almost anything they want with the project, except to distribute closed source versions. This license type was chosen with Netcaps research purpose in mind, and in the hope that it leads to further improvements and new capabilities contributed by other researchers on the long term. For more infos refer to the License page.

## Source Code Stats

Stats for netcap v0.4, generated with cloc version 1.80

> $ zeus cloc

```text
     332 text files.
     332 unique files.
     128 files ignored.

github.com/AlDanial/cloc v 1.80  T=0.17 s (1167.8 files/s, 117408.0 lines/s)
-------------------------------------------------------------------------------
Language                     files          blank        comment           code
-------------------------------------------------------------------------------
Go                             196           2692           3655          13540
Markdown                         8            106              0            517
-------------------------------------------------------------------------------
SUM:                           204           2798           3655          14057
-------------------------------------------------------------------------------
```

