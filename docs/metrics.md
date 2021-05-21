---
description: Prometheus Metrics
---

# Metrics

## Introduction

Netcap now supports exporting prometheus metrics about its go runtime, the collection process and the audit records itself. These data points can be used to gain insights about the collection performance or discover security related events.

[Prometheus](https://github.com/prometheus) is an open-source systems monitoring and alerting toolkit originally built at [SoundCloud](https://soundcloud.com/). Since its inception in 2012, many companies and organizations have adopted Prometheus, and the project has a very active developer and user [community](https://prometheus.io/community). It is now a standalone open source project and maintained independently of any company.

{% embed url="https://prometheus.io" caption="Prometheus Homepage" %}

To visualize the captured data I recomment the open source analytics and monitoring solution Grafana:

{% embed url="https://grafana.com/grafana/" caption="Grafana Homepage" %}

This feature can be used with the **export** tool, which behaves similar to **capture** but is able to operate on pcaps, audit records and network interfaces.

## Configuration

Metrics are served by default on [**127.0.0.1:7777/metrics**](http://127.0.0.1:7777/metrics). Configure a prometheus instance to scrape it:

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

{% hint style="info" %}
Tip: The latest prometheus config documentation can be found at: [https://prometheus.io/docs/prometheus/latest/configuration/configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
{% endhint %}

Run the export tool to capture live from an interface:

```text
net export -iface en0
```

{% hint style="info" %}
Tip: Use `$ net capture -interfaces` to get a list of available interfaces to choose from
{% endhint %}

Go to [http://localhost:9090](http://localhost:9090) or to the port you configured alternatively, to check if your prometheus instance is scraping data correctly. Now that we have some data at hands, lets use Grafana to visualize it!

You can setup Grafana on macOS via brew:

```text
$ brew install grafana
```

{% hint style="info" %}
Tip: On macOS, Grafanas default config is at **/usr/local/etc/grafana/grafana.ini** and installed plugins are stored at **/usr/local/opt/grafana/share/grafana/data/plugins**.
{% endhint %}

Start the prometheus server and pass the previously created config:

```text
$ prometheus --config.file prometheus/prometheus.yml
```

You need to install the pie chart plugin for grafana:

```text
$ cd /usr/local/opt/grafana/share/grafana/data/plugins
$ git clone https://github.com/grafana/piechart-panel.git --branch release-1.4.0
```

Start the grafana server:

```text
$ grafana-server --homepath /usr/local/opt/grafana/share/grafana
```

Now download the NETCAP Dashboard and import it into Grafana:

{% file src=".gitbook/assets/netcap-1587637598999 \(1\).json" %}

Go to **Settings &gt; Datasources** and a prometheus datasource, either with the default port 9090 or the one you choose in the config.

You should be good to go!

## Usage

Export a PCAP dumpfile and serve metrics .

```text
$ net export -read 2017-09-19-traffic-analysis-exercise.pcap
```

Capture and export traffic live from the named interface:

```text
$ net export -iface en0
```

Export a specific audit record file:

```text
$ net export -read HTTP.ncap.gz
```

Export all audit record files in the current directory:

```text
$ net export .
```

## Overview Dashboard Preview

![Grafana Dashboard Overview](.gitbook/assets/screenshot-2019-05-04-at-23.39.19.png)

## TCP Dashboard Preview

![Grafana Dashboard TCP](https://github.com/dreadl0ck/netcap/tree/767852a00d76fcf7c921a4f3830ae6cec0162481/docs/.gitbook/assets/screenshot-2019-05-04-at-23.39.41%20%281%29.png)

## HTTP Dashboard Preview

![Grafana Dashboard HTTP](https://github.com/dreadl0ck/netcap/tree/767852a00d76fcf7c921a4f3830ae6cec0162481/docs/.gitbook/assets/screenshot-2019-05-04-at-23.40.05%20%281%29.png)

