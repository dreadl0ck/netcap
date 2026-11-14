# Containers

Netcap ships Dockerfiles for Ubuntu and Alpine runtime images, variants without DPI (`nodpi`) and a service image for the WebUI. Pick an image from [Docker Hub](https://hub.docker.com/r/dreadl0ck/netcap/tags) or build one from the checkout.

After you pull an image, run `net --version` inside it to see which release it contains, and note the image digest in your records.

## Build locally

Use the recipes in `zeus/commands.yml` and `zeus/scripts/`. They also provide the embedded WebUI build context that the Dockerfiles need. A bare `docker build .` does not.

## Analyze a capture in a container

Offline analysis needs a read-only mount for your captures and a writable mount for the output. It does not need access to a network interface.

```sh
mkdir -p output

docker run --rm \
  --mount type=bind,src=/captures,dst=/input,readonly \
  --mount type=bind,src="$PWD/output",dst=/output \
  dreadl0ck/netcap:<tag> net capture -read /input/office-lan.pcap -out /output/audit -dpi=false
```

Replace `<tag>` with a tag from Docker Hub, or use the name of your local image. The example writes the command as `net ...`. If your image already uses `net` as its entrypoint, leave the leading `net` out.

The audit records end up in `./output/audit` on the host. Check that the user inside the container can write to the output directory.

## What each mode needs

| Mode    | You need                                                                             |
| ------- | ------------------------------------------------------------------------------------ |
| Offline | Read access to the captures and a writable output directory with enough disk         |
| Live    | A Linux network namespace that can see the interface, plus capture capabilities      |
| Service | A published port, storage for uploads and results, and authentication in front of it |
| DPI     | Native libraries, CPU architecture and build tags that match the image               |

Docker Desktop runs containers in a Linux VM, so a container there cannot see your Mac's network interfaces. Do not use privileged mode to work around this. Capture on a host or network namespace that actually carries the traffic you want.

Keep the [local WebUI/API](web-interface.md#hosting-boundary) behind the hosting boundary described there.

## Firewall containers

The [application firewall](APPLICATION_FIREWALL.md#quickstart) has its own `docker/firewall/Dockerfile`. It builds a minimal `scratch` image that runs as UID/GID 10001 and contains no libpcap, DPI or YARA. Use its Compose example or the `charts/netcap-firewall` chart. The capture-service image is not the reverse proxy.

The optional Linux enforcer has its own image and chart and works only within the namespaces you name.
