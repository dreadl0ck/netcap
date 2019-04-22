---
description: A view from above
---

# Overview

The _Netcap_ \(NETwork CAPture\) framework efficiently converts a stream of network packets into highly accessible type-safe structured data that represent specific protocols or custom abstractions. These audit records can be stored on disk or exchanged over the network, and are well suited as a data source for machine learning algorithms. Since parsing of untrusted input can be dangerous and network data is potentially malicious, implementation was performed in a programming language that provides a garbage collected memory safe runtime.

It was developed for a series of experiments in my bachelor thesis: _Implementation and evaluation of secure and scalable anomaly-based network intrusion detection_. Currently, the thesis serves as documentation until the wiki is ready, it is included at the root of this repository \(file: [mied18.pdf](https://github.com/dreadl0ck/netcap/blob/master/mied18.pdf)\). Slides from my presentation at the Leibniz Supercomputing Centre of the Bavarian Academy of Sciences and Humanities are available on [researchgate](https://www.researchgate.net/project/Anomaly-based-Network-Security-Monitoring).

The project won the 2nd Place at Kaspersky Labs SecurIT Cup 2018 in Budapest.

_Netcap_ uses Google's Protocol Buffers to encode its output, which allows accessing it across a wide range of programming languages. Alternatively, output can be emitted as comma separated values, which is a common input format for data analysis tools and systems. The tool is extensible and provides multiple ways of adding support for new protocols, while implementing the parsing logic in a memory safe way. It provides high dimensional data about observed traffic and allows the researcher to focus on experimenting with novel approaches for detecting malicious behavior in network environments, instead of fiddling with data collection mechanisms and post processing steps. It has a concurrent design that makes use of multi-core architectures. The name _Netcap_ was chosen to be simple and descriptive. The command-line tool was designed with usability and readability in mind, and displays progress when processing packets. The latest version offers 58 audit record types of which 53 are protocol specific and 5 are flow models.

