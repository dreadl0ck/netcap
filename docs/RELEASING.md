# Releasing Netcap

Run from a clean `master` that matches `origin/master`, on the release Mac.
Build Linux release images in Dokploy and package from digest-pinned images
using `NETCAP_RELEASE_IMAGES`. Build macOS locally and sign Windows through
GoReleaser.

## Prerequisites

`zeus release-preflight` checks all of these before anything is tagged:

| Requirement | How to satisfy it |
| --- | --- |
| Clean tree on `master`, equal to `origin/master` | Commit, `git pull --rebase`, push |
| Tag `vX.Y.Z` absent locally and on GitHub | Bump `VERSION` in `zeus/commands.yml` |
| `RELEASE_NOTES.md` starts with `## vX.Y.Z — title` and validates | `python3 scripts/check-release-notes.py` |
| `gh` authenticated, SSH key loaded | `gh auth status`; `ssh-add --apple-load-keychain` |
| YARA-X 1.22.0 install | `export YARA_X_PREFIX="$PWD/.native/yara-x"`; build it with `PREFIX=... sh scripts/build-yara-x.sh` |
| Docker can pull images | Docker Desktop uses a manual proxy on `127.0.0.1:1030`; start it |
| Frontend licenses readable | `pnpm install --frozen-lockfile --force` in `cmd/capture/webui/frontend` |
| Windows signing credentials | `SSL_COM_ENV_FILE`, defaulting to `../products/.env` |
| Native binary hygiene | Rust `llvm-tools` and Homebrew LLVM; Linux image receipt keys: `commit`, `builders` (`alpine`, `ubuntu`), `images` (`alpine`, `alpine-nodpi`, `ubuntu`, `ubuntu-nodpi`) |

Regenerate `types/netcap.pb.go` (`zeus gen-proto-release`) in an ordinary commit
when `types/netcap.proto` changes; the release no longer does it.

## Release

1. Write the `RELEASE_NOTES.md` entry and set `VERSION` in `zeus/commands.yml`;
   commit and push both.
2. Run the gates for the release: `make recheck-v01613` (or the newest
   `recheck-*` target) and `make try-parity`.
3. Export `YARA_X_PREFIX`. Run `zeus release-preflight`, `zeus licenses`,
   `zeus remove-dist`, `zeus gen-version`, then `zeus version-bump`.
4. Build the four Linux candidates from the pushed tag and record their digests
   plus both YARA-X builder digests in `NETCAP_RELEASE_IMAGES`. Run
   `zeus release-resume` with Homebrew LLVM on `PATH`.

| Phase | Steps | On failure |
| --- | --- | --- |
| Before the tag | `release-preflight`, `licenses` | Fix and rerun `zeus release`; nothing is public |
| Tag | `gen-version` stamps `version.go`, `version-bump` commits it and pushes `vX.Y.Z` | Rerun is refused by preflight; continue with `zeus release-resume` |
| After the tag | `release-resume`: Linux Docker builds, license sources, GoReleaser (macOS, Windows, GitHub release), macOS runtime sources, asset upload, release title | Fix the cause and run `zeus release-resume`; uploads overwrite |

A failure after the tag leaves a public tag without a release, so resume promptly.

## Verify

- `gh release view vX.Y.Z` lists 10 assets, including `checksums.txt`, both
  source bundles and the DPI and no-DPI archives for darwin-arm64, Linux libc
  and Linux musl, plus no-DPI Windows.
- Download one archive, check it against `checksums.txt`, and confirm
  `net --version` prints the release commit.
- Optional: run the `Qualify packaged release runtimes` workflow with the tag.

## Deploy try.netcap.io

try is the Dokploy application `ehTukSWyJaSFPvZ5PZxZ2` on the estate host. It
runs `registry.amsterdam-technologies.com/library/netcap-service:<tag>@<digest>`
with `/srv/netcap-try-server/data` on `/data` and
`/srv/netcap-try-server/managed-0154` on `/home/netcap/.config/netcap`.
Keep the runtime caps on the Dokploy application: `cpuLimit=4000000000`
(4 vCPUs) and `memoryLimit=12884901888` (12 GiB).

1. Build: duplicate the previous `try-release-build-*` raw compose in Dokploy.
   Replace the commit, the `ADD --checksum` value (SHA-256 of
   `https://codeload.github.com/dreadl0ck/netcap/tar.gz/<commit>`, stable across
   downloads), `VERSION`, `COMMIT` and the image tag
   `try-vX.Y.Z-<commit12>-<YYYYMMDD>`. Deploy it, then check
   `docker run --rm --entrypoint /usr/local/bin/net <image> --version` on the host.
2. Push: tag the image as `registry.amsterdam-technologies.com/library/netcap-service:<tag>`
   and push; note the digest.
3. Back up into `/root/netcap-try-vXYZ-<date>`: `docker service inspect`
   output, the config mount, the data mount and capture hashes.
4. QA: stage the 20 pinned inputs and run `make try-parity TRY_DPI=true
   TRY_BINARY=/path/to/net TRY_CHECK_FLAGS=--showcase` against the candidate.
   Also run the candidate image against an isolated copy of production data
   (loopback, `NC_GEO_PROVIDERS=dbip`). Start with fresh derived results.
   Archive legacy rule YAML outside the rules directory in the backed-up data
   volume. Public try should keep the default embedded pack; compare
   `/api/config?sessionId=…` `detectionRulePack.sha256` across all 20 runs.
   The demo captures are startup preloads from `/data/netcap-service/pcaps`,
   backed by `/srv/netcap-try-server/data/netcap-service/pcaps`. Use names and
   SHA-256 values from `scripts/try-pcaps.json`; `/api/upload` creates private
   expiring sessions. For scoring, run `scripts/score-showcase-iocs.py` with the
   replay workdir and `netcap-eval-scoring/showcase/v0.16.14` reference.
5. Deploy: set the app's image to `<tag>@<digest>` and deploy, with the
   rollback image in the deployment description. The service updates stop-first.
6. Verify: `https://try.netcap.io/api/files/input` reports 20/20 complete,
   `/api/network-interfaces` answers 403, and `net --version` in the running
   container prints the release commit.

Rollback: set the app's image back to the previous `<tag>@<digest>` and deploy.

For the optional YARA-X, Magika and KEV image, use `docker/service/Dockerfile`
target `showcase` with the named BuildKit context `showcase_enrichment` set to a
reviewed install produced by `net util --download-enrichment --enrichment-root
/path/to/snapshot`. Supply the snapshot's verified revision and digest with the
build. Confirm Magika, YARA-X and `kev.status` are available in staging before
promoting this target. `NC_SHOWCASE_FILE_CONFIG` is applied only to preloaded
captures. Any pre-existing private upload without a browser owner is accessible
only to the operator until normal service expiry.

For release builds, use a digest-pinned builder that ran `scripts/build-yara-x.sh`
with remapped paths, and set `NETCAP_RELEASE_HYGIENE=1` for Try.

## Pitfalls

- `net capture` without `-http ""` keeps its web UI running after the capture,
  so a timing harness waits forever.
- GoReleaser names the release `vX.Y.Z`; `release-title` renames it from the
  first `RELEASE_NOTES.md` heading.
