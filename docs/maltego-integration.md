---
description: Explore PCAP files as link graphs in Maltego
---

# Maltego

**Maltego** is an open source intelligence (OSINT) and link analysis tool. You run transforms on entities and see the results as a graph.

{% embed url="https://www.maltego.com" %}

A transform is a small program that fetches data and returns it as new entities in the desktop client. Netcap provides entities and transforms that let you analyze a PCAP in Maltego, focused on the behavior of the hosts and devices in the capture.

## Installation

Install `net` and check which executable the transforms will call:

```
$ which net
/usr/local/bin/net
$ net --version
```

The transforms expect `net` at `/usr/local/bin/net`. If yours is elsewhere, update the executable path in the transform configuration. Keep the native libraries that came with your release next to the binary.

To generate the Maltego configuration, run `zeus gen-maltego-config` in a source checkout. Import the result in Maltego with Import / Export Config → Import Config.

{% hint style="info" %}
Maltego transforms need a working directory. Netcap uses `/usr/local`, so the current user must be able to enter it. Nothing is written there. The logs of transforms that run the netcap core go into a separate directory for each processed PCAP.
{% endhint %}

## Load a PCAP

You have two options:

1. Drag the file into a Maltego graph. It arrives as a **maltego.File** entity with the file path in its notes. Change the entity type to **netcap.PCAP**, open its detail view, and copy the path from the **Notes** tab into the **path** property.
2. Create a new **netcap.PCAP** entity and set its **path** property to the path of your PCAP.

## Run transforms

Right-click an entity and type **Get** in the search bar to see the transforms for that entity type. You can also open the **Run View** in the **Windows** tab and start transforms with one click.

The **netcap.DeviceProfiles** entity represents the device profiles derived from a PCAP. It offers two transforms:

![](.gitbook/assets/screenshot-2020-04-22-at-11.50.20.png)

**GetDeviceProfilesWithDPI** turns on deep packet inspection. It needs extra dependencies and can slow processing down a lot. Without DPI, the transforms that depend on DPI data return nothing.

Run **GetDevices** to add the devices to the graph.

![](.gitbook/assets/screenshot-2020-04-22-at-11.50.26.png)

This adds entities of type **netcap.Device**. A device lists the contacts and addresses it used to reach network services. These are the transforms for a device:

![](.gitbook/assets/screenshot-2020-04-22-at-11.50.07.png)

They create **netcap.IPAddr** entities with information about the host and more transforms to drill down. These are the transforms for a **netcap.IPAddr**:

![netcap.IPAddr transformations](.gitbook/assets/screenshot-2020-04-22-at-11.49.53.png)

## Configuration

The **OpenFile** transform opens extracted files, except executables, in the default application for their type. On macOS it uses `open`, on Linux `gio open`. Set `NC_MALTEGO_OPEN_FILE` to use a different application.

## Examples

Find DHCP information for the selected hosts:

![](.gitbook/assets/dhcp.mov.gif)

Add the server names sent as SNI in TLS handshakes:

![](.gitbook/assets/snis.mov.gif)

List the application categories found by deep packet inspection:

![](.gitbook/assets/dpicategories2.mov.gif)

Extract a POP3 authentication token:

![](.gitbook/assets/mailtoken.mov.gif)

## Gallery

With many nodes, the organic layout keeps the graph readable:

![Graph during an investigation (organic topology)](.gitbook/assets/screenshot-2020-03-25-at-01.22.54.png)

Interaction with a PHP webshell:

![PHP webshell interaction](.gitbook/assets/screenshot-2020-03-25-at-15.00.45.png)

An exploit that injects commands through an HTTP parameter:

![HTTP parameter command injection](.gitbook/assets/screenshot-2020-03-25-at-15.00.55.png)

An investigation after the attacker was identified, with further information gathered:

![Dataset investigation](.gitbook/assets/screenshot-2020-03-25-at-00.20.06.png)

![Dataset investigation](.gitbook/assets/files.png)

![Flow Graph](.gitbook/assets/screenshot-2020-03-25-at-20.19.15.png)

## Detail Views

![](.gitbook/assets/screenshot-2020-04-22-at-11.54.48.png)

![](.gitbook/assets/screenshot-2020-04-22-at-12.01.05.png)

![](.gitbook/assets/screenshot-2020-04-22-at-12.04.55.png)

![](.gitbook/assets/screenshot-2020-04-22-at-12.02.08.png)

![](.gitbook/assets/screenshot-2020-04-22-at-12.02.03.png)

![](.gitbook/assets/screenshot-2020-04-22-at-12.03.33.png)
