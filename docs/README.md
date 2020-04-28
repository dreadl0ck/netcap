---
description: A brief overview
---

# Overview

![](.gitbook/assets/screenshot-2019-05-05-at-13.41.40-1.png)

The _Netcap_ \(NETwork CAPture\) framework efficiently converts a stream of network packets into platform neutral type-safe structured audit records that represent specific protocols or custom abstractions. These audit records can be stored on disk or exchanged over the network, and are well suited as a data source for machine learning algorithms. Since parsing of untrusted input can be dangerous and network data is potentially malicious, implementation was performed in a programming language that provides a garbage collected memory safe runtime.

It was developed for a series of experiments in my bachelor thesis: _Implementation and evaluation of secure and scalable anomaly-based network intrusion detection_. The thesis is included at the root of this repository \(file: [mied18.pdf](https://github.com/dreadl0ck/netcap/blob/master/mied18.pdf)\) and can be used to as an introduction to the framework, its philosphy and architecture. However, be aware that the command-line interface was refactored heavily and the thesis examples refer to very early versions. This documentation contains the latest API and usage examples. Slides from my presentation at the Leibniz Supercomputing Centre of the Bavarian Academy of Sciences and Humanities are available on [researchgate](https://www.researchgate.net/project/Anomaly-based-Network-Security-Monitoring).

The project won the 2nd Place at Kaspersky Labs SecurIT Cup 2018 in Budapest.

_Netcap_ uses Google's Protocol Buffers to encode its output, which allows accessing it across a wide range of programming languages. Alternatively, output can be emitted as comma separated values, which is a common input format for data analysis tools and systems. The tool is extensible and provides multiple ways of adding support for new protocols, while implementing the parsing logic in a memory safe way. It provides high dimensional data about observed traffic and allows the researcher to focus on experimenting with novel approaches for detecting malicious behavior in network environments, instead of fiddling with data collection mechanisms and post processing steps. It has a concurrent design that makes use of multi-core architectures. The name _Netcap_ was chosen to be simple and descriptive. The command-line tool was designed with usability and readability in mind, and displays progress when processing packets. The latest version offers 66 audit record types of which 55 are protocol specific and 8 are custom abstractions, such as flows or transferred files.

## Design Goals

* memory safety when parsing untrusted input
* ease of extension
* output format interoperable with many different programming languages
* concurrent design
* output with small storage footprint on disk
* gather everything, separate what can be understood from what can't
* allow implementation of custom abstractions
* rich platform and architecture support

## Framework Components

The framework consists of 9 logically separate tools compiled into a single binary:

* capture \(capture audit records live or from dumpfiles\)
* dump \(dump with audit records in various formats\)
* label \(tool for creating labeled CSV datasets from netcap data\)
* collect \(collection server for distributed collection\)
* agent \(sensor agent for distributed collection\)
* proxy \(http reverse proxy for capturing traffic from web services\)
* util \(utility tool for validating audit records and converting timestamps\)
* export \(exporter for prometheus metrics\)
* transform \(maltego transformation plugin\)

## Use Cases

* monitoring honeypots
* monitoring medical / industrial devices
* research on anomaly-based detection mechanisms
* Forensic data analysis

## Demos

A simple demonstration of generating audit records from a PCAP dump file, querying and displaying the collected information in various ways

{% embed url="https://asciinema.org/a/Mw2PldBOcPZeTOeN8XTKxFA5h" caption="Working with PCAPs" %}

And live operation decoding traffic from my wireless network interface, while I am surfing the web

{% embed url="https://asciinema.org/a/hOkjEZlTR4C9FRZ9ky7RTt2nA" caption="Live Capture" %}

Exploring HTTP audit records

{% embed url="https://asciinema.org/a/P5hwb7YzMer4CHrF6Q6NP1WjF" caption="HTTP Audit Records" %}

### Deep Learning

Watch a quick demo of the deep neural network for classification of malicious behavior, on a small PCAP dump file with traffic from the LOKI Bot. First, the PCAP file is parsed with [netcap](https://github.com/dreadl0ck/netcap-tf-dnn/blob/master/github.com/dreadl0ck/netcap), in order to get audit records that will be labeled afterwards with the [netlabel](https://github.com/dreadl0ck/netcap#netlabel-command-line-tool) tool. The labeled CSV data for the TCP audit record type is then used for training \(75%\) and evaluation \(25%\) of the classification accuracy provided by the deep neural network.

{% embed url="https://asciinema.org/a/WnnLCsPUcBWatb2ddf0xK1pmJ" caption="Deep Learning with Tensorflow" %}

## License

Netcap is licensed under the GNU General Public License v3, which is a very permissive open source license, that allows others to do almost anything they want with the project, except to distribute closed source versions. This license type was chosen with Netcaps research purpose in mind, and in the hope that it leads to further improvements and new capabilities contributed by other researchers on the long term. For more infos refer to the License page.

## Source Code Stats

Stats for netcap v0.5, generated with cloc version 1.80

> $ zeus cloc

```text
     444 text files.
     444 unique files.                                          
     158 files ignored.

github.com/AlDanial/cloc v 1.84  T=0.26 s (1090.4 files/s, 116481.5 lines/s)
-------------------------------------------------------------------------------
Language                     files          blank        comment           code
-------------------------------------------------------------------------------
Go                             277           4191           4788          21031
Markdown                         9            123              0            503
YAML                             1              5              4             14
-------------------------------------------------------------------------------
SUM:                           287           4319           4792          21548
-------------------------------------------------------------------------------
```

