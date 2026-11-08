ARG NETCAP_BUILDER_IMAGE=docker.io/dreadl0ck/netcap-builder:ubuntu-dpi-yara1.22.0-84980998-20261108@sha256:80a2254dffa4235f177d5385231468dc69426d1f47f68cc03610c8b042def670
FROM --platform=linux/amd64 ${NETCAP_BUILDER_IMAGE} AS builder
RUN pkg-config --exact-version=1.22.0 yara_x_capi
ENV GOFLAGS="-mod=readonly -p=2" GOMAXPROCS=2 RAYON_NUM_THREADS=2

# Copy netcap source
WORKDIR /netcap
COPY . .
COPY --from=netcap-webui / /netcap/cmd/capture/webui/frontend/dist/

ARG NETCAP_BUILD_VERSION=XXX
ARG NETCAP_BUILD_COMMIT=development
ENV VERSION=${NETCAP_BUILD_VERSION}

ARG TAGS="-tags noyara"
RUN echo "tags: $TAGS"

ENV CFLAGS -I/usr/local/include/
ENV LDFLAGS -ltrace -lndpi -lpcap -lm -pthread

# debug info
RUN env
RUN find / -iname ndpi_main.h
RUN find / -iname libprotoident.h
RUN find / -iname libtrace.h
RUN ls /usr/lib/*

# Extract library versions from go.mod
RUN GOPACKET_VERSION=$(go list -m -f '{{.Version}}{{with .Replace}}+{{.Version}}{{end}}' github.com/gopacket/gopacket) && \
    GO_DPI_VERSION=$(grep "github.com/dreadl0ck/go-dpi" /netcap/go.mod | grep -v indirect | awk '{print $2}') && \
    GOOS=linux GOARCH=amd64 go build ${TAGS} -trimpath \
    -ldflags "-s -w \
        -X github.com/dreadl0ck/netcap.Version=v${VERSION} \
        -X github.com/dreadl0ck/netcap.Commit=${NETCAP_BUILD_COMMIT} \
        -X github.com/dreadl0ck/netcap.GopacketVersion=${GOPACKET_VERSION} \
        -X github.com/dreadl0ck/netcap/internal/dpi.NDPIVersion=4.14.0 \
        -X github.com/dreadl0ck/netcap/internal/dpi.LibprotoidentVersion=2.0.15-2 \
        -X github.com/dreadl0ck/netcap/internal/dpi.GoDPIVersion=${GO_DPI_VERSION}" \
    -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd/net

FROM --platform=linux/amd64 ubuntu:26.04
ARG IPV6_SUPPORT=true

RUN apt-get update
RUN apt install -y --fix-missing libpcap0.8 software-properties-common ca-certificates liblzo2-2 libkeyutils-dev libnuma1 libbz2-1.0 liblz4-1 libzstd1 libstdc++6 tcpdump curl xz-utils
RUN update-ca-certificates

# Install Google Magika CLI v1.0.2 for AI-based file type classification
ARG MAGIKA_VERSION=1.0.2
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then MAGIKA_ARCH="x86_64-unknown-linux-gnu"; MAGIKA_SHA256=4ce475c965cd20e724b5fc53e8a303a479b9d8649beef8721d05e9b3988fbab4; \
    elif [ "$ARCH" = "aarch64" ]; then MAGIKA_ARCH="aarch64-unknown-linux-gnu"; MAGIKA_SHA256=55eda0c5dc9e1853ba530000815cd084c1dc654c59d52da486159b907dc9ec84; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -LsSf "https://github.com/google/magika/releases/download/cli/v${MAGIKA_VERSION}/magika-${MAGIKA_ARCH}.tar.xz" -o /tmp/magika.tar.xz && \
    echo "$MAGIKA_SHA256  /tmp/magika.tar.xz" | sha256sum -c - && \
    tar -xJOf /tmp/magika.tar.xz "magika-${MAGIKA_ARCH}/magika" > /usr/local/bin/magika && \
    chmod +x /usr/local/bin/magika && rm /tmp/magika.tar.xz

WORKDIR /netcap

COPY --from=builder /netcap/bin/* /usr/bin/
COPY --from=builder /netcap/LICENSE /usr/share/licenses/netcap/LICENSE
COPY --from=builder /netcap/legal /usr/share/licenses/netcap/
COPY --from=builder /usr/local/lib/*.so* /usr/local/lib/
COPY --from=builder /usr/lib/libndpi* /usr/lib/
RUN ldconfig && /usr/bin/net -version

CMD ["/bin/sh"]
