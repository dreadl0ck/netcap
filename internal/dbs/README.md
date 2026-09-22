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

### API Endpoints

- `GET /health` - Health check
- `GET /dbs/latest` - Latest version metadata (JSON)
- `GET /dbs/list` - List all available versions (JSON)
- `GET /dbs/latest.tar.gz` - Download latest database tarball
- `GET /dbs/YYYY-MM-DD.tar.gz` - Download specific version

### Database Storage

The database server stores files in the following structure:

```
netcap-dbs-server/          # Root directory (configurable via NC_CONFIG_ROOT)
├── dbs/                    # Database storage directory
│   ├── 2024-01-15.tar.gz  # Versioned database tarball
│   ├── 2024-01-15.json    # Metadata for version
│   ├── latest.tar.gz      # Symlink/copy of latest version
│   └── latest.json        # Symlink/copy of latest metadata
└── build/                  # Temporary build directory
```

**Configuration:**
- Set `NC_CONFIG_ROOT` environment variable to change the root directory
- Default: `netcap-dbs-server` (relative to current working directory)
- Docker default: `/data/netcap-dbs-server`

**Using Pre-existing Databases:**

The server can use pre-existing databases instead of rebuilding on startup. Simply mount or copy database files into the `dbs/` directory before starting the server. The server will:

1. Detect existing database tarballs (YYYY-MM-DD.tar.gz format)
2. Use the most recent version as the initial revision
3. Create `latest` symlinks automatically
4. Skip initial rebuild and start serving immediately
5. Continue with scheduled nightly rebuilds

For detailed instructions on mounting databases with Docker, see `docker/dbs-server/README.md`.

## TODOs

- integrate https://github.com/malware-traffic/indicators
- initJa3Resolver: index ja3 json dbs in bleve and bundle with dbs

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
- [NVD vulnerabilities indexed in a BleveDB](#nvd-vulnerabilities-indexed-in-a-bleveDB)
- [Exploit-db indexed in a BleveDB](#exploit-db-indexed-in-a-bleveDB)

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

The following data sources are included:

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

Commonly seen domains on the web, mostly from legitimate companies not known to distribute malicious software.

Be aware that some malicious domains made it into this list in the past,
but this list is still useful to filter out likely harmless traffic on big datasets.

Source: http://s3.amazonaws.com/alexa-static/top-1m.csv.zip

License: MIT

### MaxMind GeoLite2 CC Databases

For retrieving geographic City and ASN information about an IP address.

This repository contains the last version of the database that was distributed under the Creative Commons license (from the 27th of December 2019, backed up the by the web archive).

For obtaining the latest version, you have to sign up at maxmind and agree to their terms of service:

https://blog.maxmind.com/2019/12/18/significant-changes-to-accessing-and-using-geolite2-databases

To ensure the latest version is not accidentally pushed into the repository pre-commit and post-commit git hooks are used, essentially hot swapping the versions in the repository root with the CC licensed ones on every commit.

License: CC / Commercial

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

### NVD vulnerabilities indexed in a BleveDB

Used to lookup identified software products and search for known vulnerabilities.

Indexed in a [bleve](https://github.com/blevesearch/bleve) database.

Source: https://nvd.nist.gov/vuln/data-feeds#JSON_FEED

License:

    The entire NVD database can be downloaded from this web page for public use. All NIST publications are available in the public domain according to Title 17 of the United States Code, however acknowledgement of the NVD when using our information is always appreciated.

### Exploit-db indexed in a BleveDB

Used to lookup identified software products and search for applicable exploit PoC code.

Indexed in a [bleve](https://github.com/blevesearch/bleve) database.

Source: https://github.com/offensive-security/exploitdb

LICENSE: GPL-2

## Further Licensing Details

    The LICENSES file contains all licenses of data sources that provide one.
    If you think that something should not be listed here please get in touch.