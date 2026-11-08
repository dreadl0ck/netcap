# Metrics

`net export` serves Prometheus metrics from audit files, PCAP input or live
capture. CSV/JSON conversion uses `net dump` instead.

## Usage

```sh
net export -read example-audit/UDP.ncap.gz -address 127.0.0.1:7777
```

Other inputs use `-read traffic.pcap`, `-dir analysis`, or `-iface en0`.
Select the real interface with `net util -interfaces`. `-replay` applies only
when exporting audit records directly; inspect `net export -h` for that mode's
options.

## Configuration

The default endpoint is `http://127.0.0.1:7777/metrics`.
Configure a separately installed Prometheus instance:

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

Loopback is relative to Prometheus's own network namespace. A containerized
Prometheus cannot reach a host listener using its own `127.0.0.1`. Configure
connectivity deliberately before changing bind addresses.

## Interpretation

| Signal | Interpretation |
| --- | --- |
| Go/process metrics | Exporter runtime resource use |
| Record counters | Observed/processed records for enabled decoders |
| Capture/drop metrics | Read with the corresponding health witness and availability |
| Grafana dashboard | Visualization of the selected metric names/labels |

Build dashboards from the actual `/metrics` output and installed Grafana version.
Historical 2019 dashboards/plugins are not a current schema contract. A zero
application counter can mean unsupported/encrypted traffic rather than no
activity; [capture health](evidence.md) provides the qualification.

## Firewall operations

The firewall's `/metrics`, `/readyz` and `/livez` belong to its separate admin
listener, default port `9090`; `net export` does not monitor a running WAF.
With scoped `--auth-config`, `/metrics` requires a `metrics` grant; health routes
remain bearer-free. Keep admin off the application Ingress and configure
administrative TLS/Secret references as described in
[Kubernetes](APPLICATION_FIREWALL.md#kubernetes).

Read policy revision, deny versus would-deny decisions, body-budget admission and
authority readiness together. A healthy socket alone does not prove an available
policy-state database. Gateway/packet `--operations-listen` is a separate opt-in
loopback status/metrics listener; consult the exact subcommand help.
Alert SSE cursors, [webhook receipts](RULES_ENGINE.md#durable-webhook-delivery)
and enforcer lease state represent different delivery/enforcement boundaries.
