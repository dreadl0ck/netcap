# DBs

## Usage Options

Users have three options for obtaining netcap databases:

1. **Download from server** (Recommended): `net util -download-dbs`
2. **Generate locally**: `net util -generate-dbs`
3. **Set up your own database server**: See [Database Server](#database-server) section below

## Database Server

Netcap now includes a built-in HTTP server that automatically rebuilds and serves databases with nightly updates.

### Starting the Server

```bash
# Start the database server
net util -serve-dbs

# Specify custom address
net util -serve-dbs -serve-addr :9090

# With verbose logging
net util -serve-dbs -verbose
```

### Using Docker (Recommended for Production)

See `docker/dbs-server/README.md` for complete documentation.

```bash
# Quick start with docker-compose
cd docker/dbs-server
docker-compose up -d
```

### Downloading Databases

```bash
# Download from default URL (dbs.netcap.io)
net util -download-dbs

# Download from custom server
net util -download-dbs -dbs-url http://your-server:8080

# Using environment variable
export NETCAP_DBS_URL=http://your-server:8080
net util -download-dbs

# Force re-download
net util -download-dbs -force
```

### Geolocation providers

Layout 2 bundles `dbip-city-lite.mmdb` and `dbip-asn-lite.mmdb` from
[DB-IP Lite](https://db-ip.com/db/lite.php), licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Layout 1 excludes them.
`geoip-sources.json` records each release month, source URL and SHA-256.
The generator and nightly server try the current month, then the previous month;
a verified cache survives an upstream outage. Invalid MMDB types or modified
files prevent packaging. The packer uses `v2/` when `netcap.sqlite` is present;
legacy input goes to `dbs/` and excludes DB-IP. Packing v2 DB-IP inputs requires
Python 3 for manifest/hash verification.

| `-geoProviders` / `NC_GEO_PROVIDERS` | Use |
| --- | --- |
| `dbip,geolite2` | Default: DB-IP first, then optional GeoLite2 |
| `geolite2,dbip` | Prefer user-installed GeoLite2, fall back to DB-IP |
| `dbip` | Load DB-IP only |
| `geolite2` | Load GeoLite2 only |

`-geoDB=false` disables all geolocation. Location (country/city together) and
ASN fall back independently; country, city and ASN output formats are unchanged.
Each selected provider requires its City and ASN pair. Missing or corrupt
providers are skipped; an unselected provider is never used. Reloading providers
clears the lookup cache. Startup logs and `/api/dbs/status` show loaded providers
and build timestamps. The Databases page saves its order in
`$NC_CONFIG_ROOT/geoip-settings.json` (normally `~/.config/netcap/`), for new
captures. Precedence: explicit CLI/config value, environment, saved UI order,
default. UI changes override the running server's startup order for new jobs.

City estimates are approximate and monthly DB-IP Lite has lower accuracy than
its commercial edition. Anycast/mobile addresses need particular care. DB-IP
IPv6 city results with no matching DB-IP ASN are suppressed to avoid its broad
unallocated-address fallback; GeoLite2 can supply the next result. This may also
suppress legitimate IPv6 city data where the ASN database has a coverage gap.
The shared web UI footer credits DB-IP and GeoNames. Applications redistributing
or displaying the data must retain attribution and the licence link.

### Optional user-installed databases

The community archives exclude `nmap-service-probes` and every `GeoLite2-*.mmdb`.
The retired Alexa feed (`domain-whitelist.csv`) is no longer fetched or shipped.
The generator, server and `pack-dbs.sh` also exclude user-installed copies when
creating an archive.

Existing installations can fetch the republished archive with
`net util -download-dbs -force`. Extraction preserves existing local files;
remove an old community-supplied `domain-whitelist.csv` yourself if present.
Keep any whitelist you maintain locally. Nmap and MaxMind files already installed
by the user remain local.

Set `DBS_DIR` to the database directory reported by Netcap (normally
`$HOME/.config/netcap/dbs`, or `$NC_CONFIG_ROOT/dbs` when configured).

| Data | Install locally |
| --- | --- |
| Nmap service probes | Review [NPSL](https://nmap.org/npsl/), including §3's reader conditions. Copy `nmap-service-probes` from your Nmap installation (often `/usr/share/nmap/`), or use the command below. Separate downloading does not settle Netcap/NPSL compatibility. |
| MaxMind GeoLite2 | Register at [MaxMind](https://www.maxmind.com/), accept its terms and download GeoLite2 ASN and City. Extract `GeoLite2-ASN.mmdb` and `GeoLite2-City.mmdb` into `DBS_DIR`. Alternatively, set `NETCAP_GEOLITE_API_KEY` to your own license key and run `net util -download-geolite`. Do not republish these downloads. |

```bash
DBS_DIR="$HOME/.config/netcap/dbs" # replace with your configured directory
mkdir -p "$DBS_DIR"
curl --fail --location https://svn.nmap.org/nmap/nmap-service-probes \
  --output "$DBS_DIR/nmap-service-probes"
```

### API Endpoints

- `GET /health` - Health check (reports `layout`)
- `GET /dbs/v2/latest` - Latest version metadata (JSON: version, tarball, `layout`, `vulndb_schema`, `sha256`, `size`)
- `GET /dbs/v2/list` - List all available versions (JSON)
- `GET /dbs/v2/latest.tar.gz`, `GET /dbs/v2/YYYY-MM-DD.tar.gz` - Download a tarball
- `GET /dbs/latest`, `GET /dbs/<file>` - Frozen layout 1 (bleve) revision for netcap < v0.10, marked `Deprecation: true`

Layout 2 (netcap ≥ v0.10) replaces `nvd.bleve` and `exploit-db.bleve` with
one `netcap.sqlite`, readable from Go and Rust (`internal/vulndb/SCHEMA.md`).
Clients refuse a tarball whose sha256 does not match the metadata.

### Database Storage

```
netcap-dbs-server/          # Root directory (NC_CONFIG_ROOT)
├── v2/                     # Published layout 2 revisions, only the latest kept
│   ├── 2026-10-04.tar.gz
│   ├── 2026-10-04.json
│   ├── latest.tar.gz       # symlink, replaced atomically
│   └── latest.json
├── dbs/                    # Legacy layout 1; data-source removals may be republished
├── staging/                # Private to a rebuild: build/ downloads, dbs/ tarball content
├── geoip-cache/             # Verified monthly DB-IP pair and source manifest
└── build/
```

A rebuild publishes only when `netcap.sqlite` was built, so a failed NVD
download keeps the previous revision.

**Configuration:**
- Set `NC_CONFIG_ROOT` environment variable to change the root directory
- Default: `netcap-dbs-server` (relative to current working directory)
- Docker default: `/data/netcap-dbs-server`

**Using Pre-existing Databases:**

The server can use pre-existing databases instead of rebuilding on startup. Mount or copy a layout 2 tarball and its JSON into `v2/` before starting the server. The server will:

1. Detect existing database tarballs (YYYY-MM-DD.tar.gz format)
2. Use the most recent version as the initial revision
3. Create `latest` symlinks automatically
4. Skip initial rebuild and start serving immediately
5. Continue with scheduled nightly rebuilds

For detailed instructions on mounting databases with Docker, see `docker/dbs-server/README.md`.

## TODOs

- integrate https://github.com/malware-traffic/indicators
- initJa3Resolver: load ja3 json dbs into netcap.sqlite and bundle with dbs

- merge PR to add fault tolerance to build process

- integrate Ja4+ and deprecate Ja3

- add generic interface for netcap dbs, so that custom data or feeds can be easily integrated

- deprecate netcap-dbs repo

## Additiontal Data

- https://github.com/projectdiscovery/wappalyzergo
- https://github.com/trisulnsm/ja3prints
- integrate feeds from https://threatview.io
- DBs: add country blocklists: "did a user browse a flagged website?"
  - http://netzsperre.liwest.at
- DBs: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - would require to retrieve IOCs for a CVE id, maybe via greynoise.io api?

- https://hunt.io/blog/ioc-hunter-feed-attribution
- https://hunt.io/glossary/best-ioc-feeds
- https://openphish.com

- https://github.com/hslatman/awesome-threat-intelligence
- https://www.wiz.io/academy/must-follow-threat-intel-feeds
- https://abuse.ch

- https://intel.aikido.dev

- DNS blocklists - AdGuard etc

# NETCAP DBs
 
This is a collection of various _open sourced_ databases with information that [netcap](https://github.com/dreadl0ck/netcap) uses for audit record enrichment and correlation.

Some data sources are used in original form, some are preprocessed.

## Index

- [Wappalyzer Technologies Database](#wappalyzer-technologies-database)
- [Fingerbank Open Sourced DHCP Fingerprints](#fingerbank-open-sourced-dhcp-fingerprints)
- [Domain Whitelist](#domain-whitelist)
- [MaxMind GeoLite2 CC Databases](#maxmind-geolite2-cc-databases)
- [HASSHDB from AdelKa](#hasshdb-from-adelka)
- [Ja3 associated Client and Server Fingerprints](#ja3-associated-client-and-server-fingerprints)
- [Ja3 Fingerprints and UserAgents from Ja3er.com](#ja3-fingerprints-and-useragents-from-ja3er)
- [Trisul Ja3 Fingerprints](#trisul-ja3-fingerprints)
- [Macaddress.io Database](#macaddress.io-database)
- [Nmap Service Probes](#nmap-service-probes)
- [User Agent Parser Regexes](#user-agent-parser-regexes)
- [IANA Service Names to Port Numbers](#iana-service-names-to-port-numbers)
- [NVD vulnerabilities in netcap.sqlite](#nvd-vulnerabilities-in-netcapsqlite)
- [Exploit-db in netcap.sqlite](#exploit-db-in-netcapsqlite)

## TODOs
 
- integrate the new trisul ja3 repository: https://github.com/trisulnsm/ja3prints

## Installation

To **clone** this repo you need to install the LFS git plugin to handle large files.

    Apt/deb: sudo apt-get install git-lfs
    Yum/rpm: sudo yum install git-lfs
    MacOS: brew install git-lfs
    Windows: ???
    
If you want to **contribute** to the repository, you will need to install the lfs and license checker hooks with:

    ./install-hooks.sh

## Data Sources

The following catalogue includes historical sources; `DATABASE_NOTICES.txt`
describes the distributed files. Optional and retired sources are marked below.

### Wappalyzer Technologies Database

Provides common attributes of web frameworks for identification.

Source: https://github.com/AliasIO/wappalyzer/blob/master/src/technologies.json

License: MIT

### Fingerbank Open Sourced DHCP Fingerprints

Fingerprinted DHCP devices will be enriched with information from: https://raw.githubusercontent.com/karottc/fingerbank/master/upstream/startup/fingerprints.csv

It can be used to get a small fraction of the Fingerbank database for offline lookups, however beware these are likely outdated.

It is also possible to authenticate to the Fingerbank API via API key for more accurate lookups.

License: Commercial

### Domain Whitelist (Alexa Top 1 million)

Retired. `domain-whitelist.csv` is no longer fetched or shipped. A local
`rank,domain` CSV remains optional for the filtered transforms.

### MaxMind GeoLite2 CC Databases

For retrieving geographic City and ASN information about an IP address.

User-installed only; community archives exclude all `GeoLite2-*.mmdb`, including
the historical 2019 snapshots. See [installation instructions](#optional-user-installed-databases)
for account-based downloads under MaxMind's terms.

### HASSHDB from AdelKa

Various SSH fingerprints, used to enrich SSH audit records.

Source: https://raw.githubusercontent.com/0x4D31/hassh-utils/master/hasshdb

License: BSD3

### Ja3 associated Client and Server Fingerprints

Associated Ja3 client and server fingerprints for a handful of OS and browser variants.

Recorded in our lab environment during our research project for the Offensive Technologies course.

Used to increase accuracy for software identification.

Filename: ja_3_3s.json

License: MIT

### Ja3 Fingerprints and UserAgents from Ja3er.com

TLS client and server hashes and associated user agents for threat hunting, from https://ja3er.com.

Source Hashes: https://ja3er.com/getAllHashesJson

Source UserAgents: https://ja3er.com/getAllUasJson

License: None provided

### Trisul Ja3 Fingerprints

https://github.com/trisulnsm/trisul-scripts/blob/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json

TODO: integrate new repo https://github.com/trisulnsm/ja3prints

License: None provided

### Macaddress.io Database

Mac OUI to Vendor Names and registered addresses.

Source: https://macaddress.io/database-download

License: https://macaddress.io/terms-of-service

### Nmap Service Probes

User-installed only; community archives exclude `nmap-service-probes`.
See [installation instructions](#optional-user-installed-databases).

https://svn.nmap.org/nmap/nmap-service-probes

License: NPSL (https://nmap.org/npsl)

### User Agent Parser Regexes

Regular expressions to identify the software behind a useragent more accurately.

Used to create additional software audit records based on HTTP user agent observations.

Source: https://raw.githubusercontent.com/tobie/ua-parser/master/regexes.yaml

License: Apache 2

### IANA Service Names to Port Numbers

Ports mapped to services for TCP and UDP, used to enrich the service audit records.

Source: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv

### NVD vulnerabilities in netcap.sqlite

Used to lookup identified software products and search for known vulnerabilities.

Stored in `netcap.sqlite` with an FTS5 full-text index; format in `internal/vulndb/SCHEMA.md`.

Source: https://nvd.nist.gov/vuln/data-feeds#JSON_FEED

License:

    The entire NVD database can be downloaded from this web page for public use. All NIST publications are available in the public domain according to Title 17 of the United States Code, however acknowledgement of the NVD when using our information is always appreciated.

### Exploit-db in netcap.sqlite

Used to lookup identified software products and search for applicable exploit PoC code.

Stored in `netcap.sqlite` with an FTS5 full-text index; format in `internal/vulndb/SCHEMA.md`.

Source: https://github.com/offensive-security/exploitdb

LICENSE: GPL-2

## Further Licensing Details

    The LICENSES file contains all licenses of data sources that provide one.
    If you think that something should not be listed here please get in touch.
