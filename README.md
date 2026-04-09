<a href="https://netcap.io">
  <img alt="Netcap Logo" src="docs/graphics/logo.png" width="100%">
</a>

<br>

[![Go Report Card](https://goreportcard.com/badge/github.com/dreadl0ck/netcap)](https://goreportcard.com/report/github.com/dreadl0ck/netcap)
[![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://raw.githubusercontent.com/dreadl0ck/netcap/master/docs/LICENSE)
[![Golang](https://img.shields.io/badge/Go-1.25-blue.svg)](https://golang.org)
![Linux](https://img.shields.io/badge/Supports-Linux-green.svg)
![macOS](https://img.shields.io/badge/Supports-macOS-green.svg)
![windows](https://img.shields.io/badge/Supports-windows-green.svg)
[![GoDoc](https://img.shields.io/badge/GoDoc-reference-blue.svg)](https://godoc.org/github.com/dreadl0ck/netcap)
[![Homepage](https://img.shields.io/badge/Homepage-blue.svg)](https://netcap.io)
[![Documentation](https://img.shields.io/badge/Documentation-blue.svg)](https://docs.netcap.io)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fdreadl0ck%2Fnetcap.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fdreadl0ck%2Fnetcap?ref=badge_shield)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/dreadl0ck/netcap)

**Netcap** (NETwork CAPture) converts network packets into structured, type-safe Protocol Buffer audit records — designed for security monitoring, forensic analysis, and machine learning. A single Go binary with 83 packet decoders, 40+ stream decoders, and 141+ audit record types, backed by a concurrent architecture and a built-in web UI.

<a href="docs/GALLERY.md">
  <img alt="Netcap Web UI — Protocol Hierarchy" src="docs/gallery/protocol-hierarchy-sankey.png" width="100%">
</a>

<p align="center"><em>Protocol hierarchy visualization in the Netcap web UI — <a href="docs/GALLERY.md">more screenshots</a></em></p>

## Features

### Protocol Analysis

- **83 packet-layer decoders** — Ethernet, IPv4/6, TCP, UDP, DNS, DHCP, ARP, TLS ClientHello/ServerHello, ICMP, NTP, SIP, OSPF, BGP, MPLS, GRE, VXLAN, 802.11, and many more
- **40+ stream decoders** — TLS, SSH, HTTP/2, QUIC, SMB, FTP, SMTP, POP3, IMAP, IRC, Kerberos, DCERPC, and more
- **Industrial protocols** — Modbus, S7Comm, DNP3, OPC-UA, PROFINET, BACnet, CIP, IEC 62351
- **Full TCP/UDP stream reassembly** with configurable limits

### Web UI

Built-in React (Vite + TypeScript) dashboard in service mode with interactive visualizations:

- Sankey diagrams, treemaps, 3D scatter plots, geo maps, host communication graphs
- Record browsing with JSON/UI views and field-level filtering
- Protocol statistics, connection analysis, host profiling, alert management

See the [Gallery](docs/GALLERY.md) for screenshots.

### Security Analysis

- **JA4 fingerprinting** — JA4, JA4S, JA4H, JA4SSH, JA4X for TLS, HTTP, SSH, and X.509 classification
- **YARA rules** — file scanning with compiled yara-x rules for malware detection
- **Magika AI** — Google's AI-based file type classification on extracted files
- **Credential harvesting detection** — configurable protocol-aware credential capture
- **File extraction** — extract files from HTTP, FTP, SMTP, POP3, IMAP, SMB, IRC with hashing (MD5, SHA1, SHA256) and MIME detection
- **Detection rules** — 30+ YAML rule categories covering reconnaissance, exfiltration, web attacks, industrial ports, and more

### Output Formats

- **Protocol Buffers** (default) — compact binary, accessible from any language
- **CSV** — configurable separators for data analysis pipelines
- **JSON** — human-readable structured output
- **Elasticsearch** — direct bulk indexing for ELK stack analysis

### Enrichment

- DNS reverse resolution
- GeoIP geolocation (MaxMind)
- MAC vendor lookup
- Deep Packet Inspection (optional, via nDPI/libprotoident)

### Integrations

- **Prometheus + Grafana** — real-time metrics and dashboards
- **Elasticsearch + Kibana** — full-text search and visualization
- **Maltego** — 45+ OSINT entity types and transforms

### Distributed Capture

Agent/collector architecture for multi-sensor deployments with encrypted communication and configurable collection servers.

## Quick Start

Pre-built binaries are available on the [Releases](https://github.com/dreadl0ck/netcap/releases) page. To build from source:

```bash
# Build (requires libpcap)
go build -o net ./cmd/

# Build without DPI (fewer C dependencies)
go build -tags=nodpi -o net ./cmd/

# Capture from PCAP file
./net capture -read traffic.pcap

# Live capture
sudo ./net capture -iface en0

# Service mode (starts web UI)
./net capture -read traffic.pcap --service

# Service mode with hot reload (development)
air
```

## Subcommands

| Command | Description |
|---------|-------------|
| `capture` | Capture audit records from live interfaces or PCAP files; `--service` enables the web UI |
| `dump` | Read and display audit record files in CSV, JSON, or table format |
| `label` | Apply attack labels to audit records using Suricata or CSV mappings |
| `collect` | Collection server for receiving data from distributed agents |
| `agent` | Sensor agent for distributed capture on remote hosts |
| `proxy` | HTTP/HTTPS reverse proxy with MITM traffic inspection |
| `export` | Export audit records with Prometheus metrics exposure |
| `transform` | Maltego OSINT transform plugin |
| `util` | Utilities: timestamp conversion, interface listing, database generation, search indexing |
| `inject` | Inline packet manipulation via NFQueue (Linux) |
| `split` | Split audit record files |

## Docker

Pre-built images are available for multiple configurations:

| Image | Description |
|-------|-------------|
| Alpine | Minimal image with full DPI support |
| Alpine (nodpi) | Lightweight, no DPI dependencies |
| Ubuntu | Full-featured Ubuntu-based image |
| Service | Web UI service mode image |

See the [`docker/`](docker/) directory for all Dockerfiles and build variants.

## Documentation

- [Documentation](https://docs.netcap.io) — full usage guide
- [Homepage](https://netcap.io) — project homepage
- [DeepWiki](https://deepwiki.com/dreadl0ck/netcap) — AI-powered codebase exploration
- [Thesis](https://github.com/dreadl0ck/netcap/blob/master/mied18.pdf) — original research paper

## Contributing

Contributions welcome — from protocol decoder additions to core framework improvements.

**Development Setup:**
- [macOS Development Setup Guide](docs/macos-development-setup.md)
- [Installation Guide](docs/installation.md)

Please use the [bug report template](https://github.com/dreadl0ck/netcap/blob/master/docs/bugreport.md) for issue reports.

## License

Netcap is licensed under the GNU General Public License v3, which is a very permissive open source license, that allows others to do almost anything they want with the project, except to distribute closed source versions. This license type was chosen with Netcap's research purpose in mind, and in the hope that it leads to further improvements and new capabilities contributed by other researchers on the long term.

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fdreadl0ck%2Fnetcap.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fdreadl0ck%2Fnetcap?ref=badge_large)
