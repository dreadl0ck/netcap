# Netcap Web UI Gallery

Screenshots from the Netcap service mode web interface. Start the web UI with:

```bash
./net capture -read traffic.pcap --service
```

---

## Protocol Hierarchy (Sankey Diagram)

![Protocol Hierarchy Sankey Diagram](gallery/Screenshot%202025-11-22%20at%2002.57.52.png)

Sankey flow diagram showing how traffic distributes across protocol layers — from link layer through transport to application protocols. The sidebar lists all decoded protocols with packet counts and color-coded layer indicators. Useful for understanding traffic composition at a glance.

---

## Audit Record Distribution (Treemap)

![Audit Record Types Treemap](gallery/Screenshot%202025-11-22%20at%2002.58.51.png)

Treemap visualization showing the relative volume of each audit record type, grouped by protocol layer. Quickly identifies which protocols dominate a capture and how traffic breaks down across the full decoder set.

---

## Host Communication Graph

![Host Communication Graph](gallery/Screenshot%202025-11-10%20at%2012.31.26.png)

Circular chord diagram mapping connections between internal (green) and external (red) IP addresses. Node size reflects traffic volume. Reveals dominant talkers, communication patterns, and unexpected external connections.

---

## Connection Pattern Analysis (3D Scatter)

![3D Scatter Plot](gallery/Screenshot%202025-11-22%20at%2002.58.24.png)

Three-dimensional scatter plot of connection attributes. Enables visual clustering and outlier detection across multiple traffic dimensions simultaneously. Interactive rotation and zoom for detailed exploration.

---

## IP Geolocation Map

![IP Geolocation Map](gallery/Screenshot%202025-11-22%20at%2002.58.31.png)

World map showing geographic distribution of observed IP addresses using MaxMind GeoIP enrichment. Highlights traffic origins and destinations, making unexpected foreign connections immediately visible.

---

## HTTP Record Browser

![HTTP Record Browser](gallery/Screenshot%202025-11-08%20at%2013.41.29.png)

Tabular record browser with JSON detail view and field-level filtering. The example shows HTTP records filtered by `UserAgent == "Download"`. Supports browsing and filtering across all 141+ audit record types with both JSON and structured UI views.
