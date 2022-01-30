# Docker Containers

## Docker Hub

There are ubuntu and alpine linux docker containers available with netcap and dependencies (e.g: libprotoident, nDPI) preinstalled.

{% embed url="https://hub.docker.com/r/dreadl0ck/netcap/tags" %}
NETCAP on docker hub
{% endembed %}

## Pull Containers

To get the v0.5 ubuntu container:

```
$ docker pull dreadl0ck/netcap:ubuntu-v0.5
```

To get the v0.5 alpine container:

```
$ docker pull dreadl0ck/netcap:alpine-v0.5
```

## Run Containers

To run the v0.5 ubuntu container:

```
$ docker run -it dreadl0ck/netcap:ubuntu-v0.5 bash
```

To run the v0.5 alpine container:

```
$ docker run -it dreadl0ck/netcap:alpine-v0.5 ash
```

> Tip: You can use the docker run **-v** flag to mount a volume with your packet captures into the container
