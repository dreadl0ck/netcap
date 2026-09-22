---
description: Release license boundaries and verification
---

# License Compliance

Netcap release artifacts carry the project license, third-party license texts,
notices, and corresponding source archives. `./zeus/scripts/licenses.sh` is the
release gate for these materials.

## JA4 Boundary

Plain JA4 TLS client fingerprinting is implemented in `internal/ja4` under the
BSD 3-Clause terms in `internal/ja4/LICENSE-JA4`. It remains enabled in official
Netcap and Netcap Pro builds.

JA4S, JA4H, JA4L, JA4X, JA4SSH, JA4T, JA4TS, JA4TScan, JA4D, and future JA4+
methods are provided by `github.com/dreadl0ck/ja4plus`. Every Netcap integration
that imports that package requires the `ja4plus` build tag. Official artifacts
do not set that tag. Existing protobuf fields remain readable for historical
data and are empty for newly decoded records in official builds.

Local source users may opt in with:

```bash
go build -tags ja4plus -o net ./cmd/net/
```

The external package is governed by the FoxIO License 1.1. Enabling the tag does
not grant commercial, hosted, managed-service, or other monetized use. Netcap
Pro must not enable this tag without appropriate OEM rights.

The JA4+ resolver accepts only a locally supplied database. Netcap does not
download a JA4 database automatically.

## Verification

`./zeus/scripts/check-ja4-build.sh` checks that official build-tag combinations
exclude `github.com/dreadl0ck/ja4plus` and that an opt-in build includes it. CI
builds, vets, and tests both the official path and the optional tagged path.

Run the complete compliance checks with:

```bash
./zeus/scripts/licenses.sh
go test -short -tags='nodpi noyara' ./...
go test -short -tags='nodpi noyara ja4plus' ./...
```

## User Access

The CLI exposes the legal documents embedded in the binary:

```bash
net licenses
net licenses legal/THIRD_PARTY_LICENSES.txt
net licenses --all
```

Netcap Pro generates an offline catalog from the exact production Go and npm
dependency graphs during its frontend build. Both direct and App Store editions
provide the catalog under Settings > Open Source Licenses. Its generator rejects
Netcap revisions that predate the JA4+ build boundary.

## OEM Follow-up

If JA4+ is licensed for official distribution, record the OEM grant, approved
products and deployment models, term, reporting obligations, attribution, and
patent terms before changing release tags. Then update the build-boundary test,
notices, source offer, and both product license catalogs in the same change.
