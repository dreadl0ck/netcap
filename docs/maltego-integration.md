---
description: Graphical link analysis to the rescue!
---

# Maltego Integration

## Introduction

**Maltego** is an open source intelligence \(OSINT\) and graphical link analysis tool for gathering and connecting information for investigative tasks.

{% embed url="https://www.maltego.com" caption="" %}

It allows to transform data using external knowledge and visualize the results in a graph topology.

Transforms are small pieces of code that automatically fetch data from different sources and return the results as visual entities in the desktop client. Transforms are the central elements of Maltego which enable its users to unleash the full potential of the software whilst using a point-and-click logic to run analyses.

Netcap provides a set of entities and transformations to analyze packet capture dump files in Maltego!

The current implementation focuses on behavorial analysis of entities within the traffic dump.

## Installation

Ensure netcap **&gt;= v0.5** is installed and can be found in **$PATH**:

```text
$ net -version
v0.5
```

Ensure the **net** binary is placed in **/usr/local/bin**:

```text
$ which net
/usr/local/bin/net
```

{% hint style="info" %}
Transformations in maltego have to specify a working directory. Currently /**usr/local** is used for this so make sure the current user has sufficient right to enter the directory. No data will be written there, all logs from transformations that invoke the netcap core are written into dedicated directories for each processed pcap file.
{% endhint %}

Next, download install the maltego transformations and enities for netcap:

Currently there are **20 entities** and **42 transformations** implemented. You can download them here:

{% file src=".gitbook/assets/netcap-maltego-config-v0.5.mtz \(2\) \(1\).zip" %}

Import them into Maltego in the "**Import / Export Config**" tab under "**Import Config**".

## Loading PCAP files into Maltego

To load a pcap file into maltego you have two options:

1\) Drag and Drop the file into a maltego graph. The files type will be **maltego.File** by default, and the path to the file on disk is set as a note on the entity.

Now, change the entities type to **netcap.PCAP**, and double click it to open the detail view. Copy the filesystem path from the **Notes** tab into the **path** property of the PCAP entity.

2\) Create a new **netcap.PCAP** entity and set the **path** property to the path of your pcap file on disk

## Running Transformations

Right click an entity and start typing **Get** into the search bar to see all available transformations for the selected type. Alternatively you can also use the **Run View** in the **Windows** tab to see and launch available transformations with a single click.

Transformations are usually bound to specific entities. For example, the **netcap.DeviceProfiles** entity, which represents the device profiles that have been derived from an input PCAP file, currently only offers the following two transformations:

![](.gitbook/assets/screenshot-2020-04-22-at-11.50.20.png)

**GetDeviceProfilesWithDPI** enables deep packet inspection, which requires to install dependencies and can slow down the processing drastically. When not using DPI the transformations making use of this data will simply return no results.

To add the actual devices to the graph, use the **GetDevices** transformation.

![](.gitbook/assets/screenshot-2020-04-22-at-11.50.26.png)

This bring the first usable entities to the graph, of type **netcap.Device**. A device has contacts and addresses it has been using to access network services by itself. When selecting a device entity, you will see the following transformations:

![](.gitbook/assets/screenshot-2020-04-22-at-11.50.07.png)

The generated entities will be of type **netcap.IPAddr** and contain information about the host, as well as a set of transforms to further drill down and investigate.

When selecting an entity of type **netcap.IPAddr**, the following transformations are offered:

![netcap.IPAddr transformations](.gitbook/assets/screenshot-2020-04-22-at-11.49.53.png)

## Configuration

Netcap offers an **OpenFile** maltego transform, which will pass filetypes except for executables to the default system application for the corresponding file format. On macOS the open utility will be used for this and on the linux the default is gio open. You can override the application used for this by setting **NC\_MALTEGO\_OPEN\_FILE**.

## Examples

Search for DHCP information from the selected hosts:

![](.gitbook/assets/dhcp.mov.gif)

Add Server Names provided as SNI on the TLS handshake:

![](.gitbook/assets/snis.mov.gif)

Use Deep Packet Inspection to list all identified application categories:

![](.gitbook/assets/dpicategories2.mov.gif)

Extraction of a POP3 authentication token:

![](.gitbook/assets/mailtoken.mov.gif)

## Gallery

When working with larger amount of nodes, the organic topology can be useful:

![Graph during an investigation \(organic topology\)](.gitbook/assets/screenshot-2020-03-25-at-01.22.54.png)

Example of interaction with a PHP webshell:

![PHP webshell interaction](.gitbook/assets/screenshot-2020-03-25-at-15.00.45-1.png)

Example of an exploit abusing a HTTP parameter command injection vulnerability:

![HTTP parameter command injection](.gitbook/assets/screenshot-2020-03-25-at-15.00.55.png)

Graph during an investigation where the attacker has been identified and further information is gathered:

![Dataset investigation](.gitbook/assets/screenshot-2020-03-25-at-00.20.06.png)

![Dataset investigation](.gitbook/assets/screenshot-2020-03-24-at-23.52.23.png)

![Flow Graph](.gitbook/assets/screenshot-2020-03-25-at-20.19.15.png)

## Detail Views

![](.gitbook/assets/screenshot-2020-04-22-at-11.54.48.png)

![](.gitbook/assets/screenshot-2020-04-22-at-12.01.05.png)

![](.gitbook/assets/screenshot-2020-04-22-at-12.04.55.png)

![](.gitbook/assets/screenshot-2020-04-22-at-12.02.08.png)

![](.gitbook/assets/screenshot-2020-04-22-at-12.02.03.png)

![](.gitbook/assets/screenshot-2020-04-22-at-12.03.33.png)

