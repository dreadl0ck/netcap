# Docker Containers

## Docker Hub

There are ubuntu and alpine linux docker containers available with netcap and dependencies \(e.g: libprotoident, nDPI\) preinstalled.

{% embed url="https://hub.docker.com/r/dreadl0ck/netcap/tags" caption="NETCAP on docker hub" %}

## Pull Containers

To get the v0.5 ubuntu container:

```text
$ docker pull dreadl0ck/netcap:ubuntu-v0.5
```

To get the v0.5 alpine container:

```text
$ docker pull dreadl0ck/netcap:alpine-v0.5
```

## Run Containers

To run the v0.5 ubuntu container:

```text
$ docker run -it dreadl0ck/netcap:ubuntu-v0.5 bash
```

To run the v0.5 alpine container:

```text
$ docker run -it dreadl0ck/netcap:alpine-v0.5 ash
```

> Tip: You can use the docker run **-v** flag to mount a volume with your packet captures into the container

