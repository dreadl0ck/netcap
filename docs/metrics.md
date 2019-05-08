---
description: Prometheus Metrics
---

# Metrics

## Introduction

Netcap now support exporting prometheus metrics about its go runtime, the collection process and the audit records itself. This feature can be used with the **net.export** tool.

## Configuration

Metrics are served by default on **127.0.0.1:7777/metrics**. Configure a prometheus instance to scrape it:

```yaml
# reference: https://prometheus.io/docs/prometheus/latest/configuration/configuration/

global:
  scrape_interval: 15s
  scrape_timeout: 15s
  #evaluation_interval: 15s

scrape_configs:
  # process_ metrics
  - job_name: netcap
    metrics_path: /metrics
    scheme: http
    static_configs:
      - targets:
        - 127.0.0.1:7777
```

## Usage

Export a PCAP dumpfile and serve metrics .

```text
$ net.export -r 2017-09-19-traffic-analysis-exercise.pcap
```

Capture and export traffic live from the named interface:

```text
$ net.export -iface en0
```

Export a specific audit record file:

```text
$ net.export -r HTTP.ncap.gz
```

Export all audit record files in the current directory:

```text
$ net.export .
```

## Overview Dashboard Preview

![Grafana Dashboard Overview](.gitbook/assets/screenshot-2019-05-04-at-23.39.19.png)

## TCP Dashboard Preview

![Grafana Dashboard TCP](.gitbook/assets/screenshot-2019-05-04-at-23.39.41.png)

## HTTP Dashboard Preview

![Grafana Dashboard HTTP](.gitbook/assets/screenshot-2019-05-04-at-23.40.05.png)

