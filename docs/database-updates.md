# Database updates

Netcap enriches captures with local databases: NVD CVEs, geolocation, port names, user-agent signatures, HASSH and a domain popularity ranking. The updater downloads them as signed data and checks the signature against an Ed25519 root built into the binary. You do not need an API key.

## Install and update

```sh
net util -download-dbs
net util -update-dbs
```

Use the same `NC_CONFIG_ROOT` when you install and when you capture. The databases live in `~/.config/netcap/dbs`, or in `$NC_CONFIG_ROOT/dbs` if the variable is set. To replace an existing installation, run `net util -download-dbs -force`.

## How an update works

The updater downloads into a staging area and verifies every file before it replaces anything. If an update fails, your previous installation stays in place. Data that has not changed is not downloaded again.

Installed data keeps working offline after an update expires. The expiry only stops the updater from accepting an old update as current.

## What the databases contain

| Data                                 | File or source                                |
| ------------------------------------ | --------------------------------------------- |
| CVEs                                 | NVD                                           |
| IP geolocation and ASN               | DB-IP Lite                                    |
| Port names                           | IANA                                          |
| Software and OS signatures           | UA-parser                                     |
| SSH client and server identification | pinned BSD HASSH catalogue                    |
| Domain popularity                    | NetAPI Top 1M (`netapi-top1m.csv`, CC BY 4.0) |

Exploit-DB payloads, Nmap probes, macaddress.io data, the Alexa list and JA3 identification lists are not included. NVD reference URLs are stored as links, and Netcap does not download the pages behind them.

## Private publisher

If you host your own databases, give the updater both the registry path and its SHA-256 pin. Get both from a source you verified independently.

## Troubleshooting

| Symptom                                | What to do                                                                                                 |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| HTTP 410, or no refreshes arrive       | Your `net` executable is too old for the download protocol. Upgrade `net`.                                 |
| SQLite schema 1                        | Download the databases again to get schema 2.                                                              |
| Update expired                         | Check the system clock and whether the publisher is still publishing.                                      |
| Registry mismatch                      | Remove any private-publisher override you did not intend, or supply the correct registry and pin together. |
| Lock unavailable                       | Check that no other updater is running, then remove the stale `.dbs-install.lock`.                         |
| No enrichment in the output            | Check the configuration root and the resolver flags.                                                       |
| Missing GeoLite2                       | Community data uses DB-IP. GeoLite2 needs a MaxMind account and licence. See [Resolvers](resolvers.md).    |
| CVE listed without a confirmed version | See [Vulnerability applicability](vulnerability-analysis.md).                                              |

Check [readiness](https://dbs.netcap.io/ready) to see whether the database server is up, and [freshness](https://dbs.netcap.io/freshness) for failed or stuck refreshes and renewal warnings. The [publisher runbook](https://github.com/dreadl0ck/netcap/blob/master/internal/dbs/README.md) covers source policies, key rotation and rollback.
