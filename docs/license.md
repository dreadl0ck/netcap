# License

## GNU General Public License v3.0

The public Go Netcap source is GPL-3.0-or-later. GPL is a strong-copyleft
license; the historical description of it as “very permissive” was incorrect.
See the [project LICENSE](https://github.com/dreadl0ck/netcap/blob/v0.15.2/LICENSE)
and source-file notices for the actual terms.

## Third-party components and data

| Material | Applicable inventory |
| --- | --- |
| Go/native dependencies | Release `legal/` notices and bundled source assets |
| Native runtime | `native-runtime-inventory.json` and runtime source archive |
| Enrichment datasets | `DATABASE_NOTICES.txt` and `RELEASE_MANIFEST.json` |
| Plain JA4 TLS fingerprint | BSD terms included with the implementation |
| Optional JA4+ source build | Separate opt-in terms; excluded from official binaries |
| Standalone firewall | Netcap GPL terms plus bundled Go module notices; `docker/firewall/Dockerfile` retains `/legal/BUILD_MODULES.txt` and module licenses |
| Coraza / CRS | Optional linked engine and embedded rule-set notices travel with the firewall package; Netcap licensing does not replace their terms |

`net licenses -h` describes the executable's license inspection commands.
A license for Netcap does not replace third-party data/runtime obligations.
[Database updates](database-updates.md) records source provenance and retired
catalogues.

## Commercial License

An alternative commercial license is available for covered Netcap code. The
[commercial agreement](COMMERCIAL-LICENSE.md) is a template with placeholders;
it does not itself grant rights until the parties agree and execute it. Its
third-party component exclusions still apply.

## Usage Disclaimer

The GPL warranty disclaimer applies. Qualify the release, enabled features and
capture completeness for your use case with [tests](tests.md) and
[health evidence](evidence.md). An alert, software fingerprint or reconstructed
file is evidence to evaluate rather than a guarantee of compromise or safety.
