ARG NETCAP_BUILDER_IMAGE
FROM --platform=linux/amd64 ${NETCAP_BUILDER_IMAGE} AS builder
RUN pkg-config --exact-version=1.22.0 yara_x_capi

# Copy netcap source
WORKDIR /netcap
COPY . .
COPY --from=netcap-webui / /netcap/cmd/capture/webui/frontend/dist/

ENV VERSION XXX

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
RUN GOPACKET_VERSION=$(grep "github.com/gopacket/gopacket" /netcap/go.mod | grep -v indirect | awk '{print $2}') && \
    GO_DPI_VERSION=$(grep "github.com/dreadl0ck/go-dpi" /netcap/go.mod | grep -v indirect | awk '{print $2}') && \
    GOOS=linux GOARCH=amd64 go build ${TAGS} -trimpath \
    -ldflags "-s -w \
        -X github.com/dreadl0ck/netcap.Version=v${VERSION} \
        -X github.com/dreadl0ck/netcap.GopacketVersion=${GOPACKET_VERSION} \
        -X github.com/dreadl0ck/netcap/internal/dpi.NDPIVersion=4.14.0 \
        -X github.com/dreadl0ck/netcap/internal/dpi.LibprotoidentVersion=2.0.15-2 \
        -X github.com/dreadl0ck/netcap/internal/dpi.GoDPIVersion=${GO_DPI_VERSION}" \
    -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd/net

FROM --platform=linux/amd64 ubuntu:26.04
ARG IPV6_SUPPORT=true

RUN apt-get update
RUN apt install -y --fix-missing libpcap0.8 software-properties-common ca-certificates liblzo2-2 libkeyutils-dev libnuma1 libbz2-1.0 liblz4-1 libzstd1 tcpdump curl xz-utils
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
COPY --from=builder /usr/local/lib/* /usr/lib/
COPY --from=builder /usr/lib/libndpi* /usr/lib/
COPY --from=builder /usr/lib/libprotoident.so* /usr/lib/
COPY --from=builder /usr/lib/libflowmanager.so* /usr/lib/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libtrace.so* /usr/lib/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libwandio.so* /usr/lib/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libwandder.so* /usr/lib/
COPY --from=builder /usr/lib/x86_64-linux-gnu/librte_eal.so* /usr/lib/
COPY --from=builder /usr/lib/x86_64-linux-gnu/librte_ethdev.so* /usr/lib/
COPY --from=builder /usr/lib/x86_64-linux-gnu/librte_mbuf.so* /usr/lib/
COPY --from=builder /usr/lib/x86_64-linux-gnu/librte_mempool.so* /usr/lib/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 /usr/lib/
COPY --from=builder /usr/lib/x86_64-linux-gnu/libssl.so.1.1 /usr/lib/
RUN ldconfig && /usr/bin/net -version

CMD ["/bin/sh"]
