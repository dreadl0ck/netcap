# Docker Containers

The repository contains Ubuntu/Alpine runtime recipes, nodpi variants and a
service image. Select a matching source revision and inspect its recipe before
building; old `ubuntu-v0.5`/`alpine-v0.5` images do not represent Go v0.15.2.

## Docker Hub

[Published tags](https://hub.docker.com/r/dreadl0ck/netcap/tags) are a registry
inventory, not proof of the source revision running inside an image. Record the
image digest and check `net --version` inside it. No current tag is assumed here.

## Pull Containers

Use an exact tag/digest that you have verified. For a local build, use the
checkout's `zeus/commands.yml` and `zeus/scripts/` recipes; they also supply the
embedded WebUI build context required by Dockerfiles. A bare `docker build .`
does not supply that named context.

## Run Containers

Current source pins matched YARA-X `1.22.0` builders and verifies the C API with
`pkg-config --exact-version=1.22.0 yara_x_capi` before compiling. Alpine capture
and service runtimes use `3.24.4`; the separately packaged firewall enforcer
retains its own pinned runtime. Do not substitute that runtime for the capture
builder (`docker/alpine*/Dockerfile`, `docker/service/Dockerfile`,
`docker/enforcer/Dockerfile`).

`scripts/qualify-native-builder.sh` checks actual YARA compile/match/nonmatch/
invalid-source behavior and libpcap BPF match/nonmatch inside the target builder.
`scripts/native-runtime-smoke.py` checks packaged execution; generated local
service recipes retain the selected matched builder. A successful emulated build
does not qualify native execution on another CPU/OS. Retain image digest,
architecture, package inventory and the actual smoke report.

Offline analysis needs an input mount and writable output, not access to a host
capture interface. For a locally verified image named `netcap-local`:

```sh
docker run --rm \
  --mount type=bind,src="$PWD/input",dst=/input,readonly \
  --mount type=bind,src="$PWD/output",dst=/output \
  netcap-local net capture -read /input/traffic.pcap -out /output/audit -dpi=false
```

Create `input`/`output` first and place the capture in `input/traffic.pcap`.
Check the image's entrypoint: this example assumes the shell-style runtime
images, where the command is explicitly `net`.

| Mode | Additional boundary |
| --- | --- |
| Offline | Host ownership/permissions and disk budget for output |
| Live | Linux network namespace, interface visibility and capture capabilities |
| Service | Published listener, uploads/storage budgets and authentication boundary |
| DPI | Matching native libraries, architecture and build tags |

Docker Desktop's Linux VM does not automatically expose a macOS host interface.
Do not use privileged mode as a substitute for selecting the right observation
point. Keep the [local WebUI/API](web-interface.md#hosting-boundary) behind its
intended hosting boundary.

## Firewall containers

The [application firewall](APPLICATION_FIREWALL.md#quickstart) has a separate
`docker/firewall/Dockerfile`: CGO-free `scratch`, UID/GID 10001, embedded
Coraza/HTTP/3, no libpcap/DPI/YARA runtime. Use its Compose example or
`charts/netcap-firewall`; the capture-service image is not this reverse proxy.
The optional Linux enforcer has its own image/chart and named-namespace scope.
