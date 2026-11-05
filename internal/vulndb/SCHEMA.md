# netcap.sqlite

Vulnerability and exploit database shared by netcap (Go, `internal/vulndb`)
and netcap-rs. One SQLite 3 file with FTS5. Replaces `nvd.bleve` and
`exploit-db.bleve` from netcap < v0.10, which only Go could read.

Any change to a table, a tokenizer or the queries below bumps
`schema_version`; readers refuse other versions.

## Tables

| table | columns | notes |
| --- | --- | --- |
| `meta` | `key`, `value` | `format=netcap-vulndb`, `schema_version=2`, `built_at`, `nvd_start_year`, `nvd_count`, `exploit_count` |
| `nvd` | `rowid` INTEGER PRIMARY KEY, `id` (unique), `description`, `severity`, `v2_score`, `access_vector`, `attack_complexity`, `confidentiality_impact`, `integrity_impact`, `availability_impact`, `base_score` REAL, `base_severity`, `configurations` TEXT | Full NVD 2.0 applicability tree as JSON; English description and CVSS fields |
| `nvd_versions` | `nvd_rowid`, `version` | Exact version strings per CVE, from vulnerable CPE matches (`versionStartIncluding` plus up to 20 patch versions before `versionEndExcluding`, else the CPE version field), else the first `\d+\.\d+\.?\d*` in the description |
| `nvd_fts` | `description` | FTS5, external content `nvd`, `tokenize='unicode61'` |
| `nvd_products` | `nvd_rowid`, `part`, `vendor`, `product` | Indexed concrete vulnerable CPE identities; candidate selection only |
| `exploits` | `id` (unique), `file`, `description`, `date`, `author`, `type`, `platform`, `port` | Exploit-DB `files_exploits.csv` by column name; `file` is relative to the bundled `exploitdb/` folder |
| `exploits_fts` | `description` | FTS5, external content `exploits`, `tokenize='unicode61'` |
| `exploit_cves` | `exploit_id`, `cve_id` | Exact CVE references from the Exploit-DB `codes` column; no title-based applicability |

## Queries

A term becomes an FTS5 phrase: trim it, drop it if it has no letter or digit,
double every `"`, wrap in `"`. Phrases are joined with ` AND `. Results are
ordered by `bm25(...)`, then `id`, and capped at 10.

| lookup | match | extra condition | empty result when |
| --- | --- | --- | --- |
| vulnerabilities(vendor, product, version) | concrete CPE part/vendor/product from `nvd_products` | Evaluate stored AND/OR/negation tree with exact versions and inclusive/exclusive numeric bounds | identity/version unknown, no positively matched vulnerable branch, or unsatisfied/unobserved prerequisites |
| exploits(vendor, product, version) | `exploit_cves` joined to applicable CVEs | Deterministic exploit-ID results, capped at 10 | no structured CVE association |
| VulnerabilityCandidates / ExploitCandidates | FTS phrases described above | Historical text/version search only | no phrase; NVD candidates also require a version |

Text candidates never establish applicability. Unknown OS, edition or target
prerequisites remain unknown; numeric range ordering is not guessed for suffix
versions. Display-name aliases are explicit in `applicability.go`. Runtime findings
retain the observed host and match status; unresolved hosts are not enriched.

Schema 1 readers must not consume schema 2. Rebuild from the NVD feeds and
Exploit-DB with `net util --generate-dbs`; download/serve metadata announces
`vulndb_schema=2`. Other readers, including netcap-rs, must implement schema 2
before consuming these snapshots.

## Reference results

`go test ./internal/vulndb ./internal/dbs` pins the query semantics on small
fixtures. A schema-1 build from the 2002–2026 NVD feeds and Exploit-DB on
2026-10-04 holds 400,976 CVEs, 2,233,579 version rows and 46,698 exploits in
299 MB (bleve: 4.1 GB), built in 22 s with a 70 MB peak footprint.
