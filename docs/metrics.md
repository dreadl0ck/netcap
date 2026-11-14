# Metrics

`net export` serves Prometheus metrics from audit files, a PCAP or a live capture. Scrape them with Prometheus and graph them in Grafana. To convert audit records to CSV or JSON, use `net dump` instead.

## Export metrics

Export a finished audit file:

```sh
net export -read example-audit/UDP.ncap.gz -address 127.0.0.1:7777
```

Other inputs:

* `-read traffic.pcap` for a PCAP
* `-dir analysis` for a directory of audit records
* `-iface en0` for a live capture. Find your interface name with `net util -interfaces`.

For a live sensor on a server, run `net export -iface eth0 -address 0.0.0.0:7777` and restrict who can reach port 7777. `-replay` works only when exporting audit records directly. Run `net export -h` for its options.

The metrics are at `http://127.0.0.1:7777/metrics` by default. Open them with `curl` to see the metric names you can graph:

```sh
curl -s http://127.0.0.1:7777/metrics | less
```

## Scrape with Prometheus

Add a job to your `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  scrape_timeout: 10s
scrape_configs:
  - job_name: netcap
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:7777"]
```

If Prometheus runs in a container, `127.0.0.1` is the container itself, not the host. Start `net export` on an address the container can reach, and use that address as the target.

## Graph in Grafana

Add Prometheus as a data source in Grafana and build panels from the metric names in your `/metrics` output.

| Metrics          | What they show                                                                  |
| ---------------- | ------------------------------------------------------------------------------- |
| Go and process   | CPU and memory use of the exporter                                              |
| Record counters  | Records processed by each enabled decoder                                       |
| Capture and drop | Packets seen and dropped; read them together with [capture health](evidence.md) |

A counter that stays at zero can mean the traffic is encrypted or no enabled decoder handles it. [Capture health](evidence.md) tells you which.

## Firewall metrics

The firewall serves `/metrics`, `/readyz` and `/livez` on its own admin listener, port `9090` by default. `net export` does not monitor a running firewall.

With a scoped `--auth-config`, `/metrics` requires a `metrics` grant. The health routes need no bearer token. Keep the admin listener off the application Ingress and configure its TLS and Secret references as described in [Kubernetes](APPLICATION_FIREWALL.md#kubernetes).

Watch these together: policy revision, deny and would-deny decisions, body-budget admission and authority readiness. A responding admin port does not mean the policy-state database is available.

Gateway and packet modes have an optional `--operations-listen` status and metrics listener on loopback. Run the subcommand's `-h` for details. Alert SSE cursors, [webhook receipts](RULES_ENGINE.md#durable-webhook-delivery) and enforcer lease state are tracked separately.
