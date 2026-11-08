# Database updates

Go v0.15.2 and Rust v0.1.9 install signed community data using an embedded Ed25519 verification root. No community API key is required.

## Install and Update

```sh
net util -download-dbs
net util -update-dbs
```

Use the same `NC_CONFIG_ROOT` when installing and capturing. Defaults are `~/.config/netcap/dbs`, or `$NC_CONFIG_ROOT/dbs`. Go users can force replacement with `net util -download-dbs -force`.

## Compatibility

| Client/data          | Action                                                                        |
| -------------------- | ----------------------------------------------------------------------------- |
| Signed clients       | Use `/dbs/signed/v1/`; verify signatures, expiry, sequence and hashes         |
| Go v0.14.0           | Frozen `/dbs/v3/` snapshot; upgrade for ongoing refreshes                     |
| Legacy v1/v2 clients | HTTP 410; upgrade the executable                                              |
| SQLite schema 1      | Download schema 2; editing a version field does not migrate tables or queries |
| Private publisher    | Supply both independently verified registry path and SHA-256 pin              |

## Verification

Updates validate complete source/member records through staging. Failure preserves the previous installation. Unchanged verified data can skip archive downloading. Verified installed data remains usable offline after update expiry; expiry prevents accepting an old update as fresh.

Community data contains NVD, DB-IP Lite, IANA, UA-parser, pinned BSD HASSH and NetAPI Top 1M (`netapi-top1m.csv`, CC BY 4.0). It excludes Exploit-DB payloads, Nmap probes, macaddress.io, Alexa, JA3 identification corpora and legacy CMS/DHCP OS catalogues. NVD reference URLs remain metadata; the updater does not fetch their bodies.

The legacy resolver ZIP attachment is retired. Use the signed updater above;
historical Git revisions and their source archives are not current database
releases, and their availability does not establish dataset redistribution rights.

## Troubleshooting

| Symptom            | Check                                                                                           |
| ------------------ | ----------------------------------------------------------------------------------------------- |
| HTTP 410           | Upgrade the executable; v1/v2 distribution is retired                                           |
| Expired update     | Check the clock and publisher freshness; retain signature/expiry checks                         |
| Registry mismatch  | Remove unintended private-publisher overrides or supply the correct independently verified pair |
| Lock unavailable   | Confirm another updater has stopped before handling a stale `.dbs-install.lock`                 |
| No enrichment      | Check configuration root and resolver flags                                                     |
| Missing GeoLite2   | Community data uses DB-IP; GeoLite2 needs separately accepted MaxMind terms                     |
| CVE text candidate | Unknown product/version/environment is not a confirmed vulnerability                            |

[Readiness](https://dbs.netcap.io/ready) checks serving; [freshness](https://dbs.netcap.io/freshness) also reports failed/stuck refreshes and renewal warnings. The [publisher runbook](https://github.com/dreadl0ck/netcap/blob/master/internal/dbs/README.md) documents source policies, root-authorized key rotation and higher-sequence rollback.
