# License

## GNU General Public License v3.0

The Netcap source is GPL-3.0-or-later. The GPL is a strong-copyleft license. See the [project LICENSE](https://github.com/dreadl0ck/netcap/blob/v0.15.2/LICENSE) and the source-file notices for the terms.

## Third-party components and data

| Material                   | Applicable inventory                                                                                                                 |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Go/native dependencies     | Release `legal/` notices and bundled source assets                                                                                   |
| Native runtime             | `native-runtime-inventory.json` and runtime source archive                                                                           |
| Enrichment datasets        | `DATABASE_NOTICES.txt` and `RELEASE_MANIFEST.json`                                                                                   |
| Plain JA4 TLS fingerprint  | BSD terms included with the implementation                                                                                           |
| Optional JA4+ source build | Separate opt-in terms; excluded from official binaries                                                                               |
| Standalone firewall        | Netcap GPL terms plus bundled Go module notices; `docker/firewall/Dockerfile` retains `/legal/BUILD_MODULES.txt` and module licenses |
| Coraza / CRS               | Optional linked engine and embedded rule-set notices travel with the firewall package; Netcap licensing does not replace their terms |

`net licenses -h` describes the license inspection commands. The Netcap license does not replace the terms of third-party data and runtimes. [Database updates](database-updates.md) records the source of each dataset and the catalogues that were retired.

## Commercial License

A commercial license is available as an alternative for covered Netcap code. The [commercial agreement](COMMERCIAL-LICENSE.md) is a template with placeholders. It grants no rights until both parties agree and sign it. Its exclusions for third-party components still apply.

## Usage Disclaimer

The GPL warranty disclaimer applies. Before you rely on a release, test the features you use and check capture completeness with the [tests](tests.md) and the [health evidence](evidence.md). An alert, software fingerprint or reconstructed file is evidence for you to evaluate. It does not guarantee compromise or safety.
