---
description: Detailed Version History Information
---

# Changelog

## v0.5 - April 2020

### Fixed

* multiple bugs in the stream reassembly
* several panics during parsing in gopacket 

### Changed

* CLI interface refactored: single binary app with subcommands, stripped size ~**17MB**
* Updated units tests
* Documentation updates
* Updated Docker containers for **Ubuntu** and **Alpine**
* Compiled with **Go 1.14.2**
* removed custom audit records Link-, Network- and TransportFlow

### New Features

* **Maltego** integration
* **File** audit records
* **Diameter** protocol audit records
* **SMTP** audit records
* **POP3** support for extracting Mails
* **JA3S** support and separate audit record for **TLSServerHello**
* New configuration options: via **environment variables** or **configuration** file
* Resolvers package for **Geolocation**, **DNS** and **Service** lookups and **whitelisting**
* Deep Packet Inspection via **nDPI** and **libprotoident**
* **DeviceProfile** Audit records, to capture the behavior of a single device within a traffic dump
* Added an integration for **bash-completion** support

