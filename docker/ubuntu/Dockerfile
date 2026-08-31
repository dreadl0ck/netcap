FROM --platform=linux/amd64 dreadl0ck/netcap-builder:ubuntu-dpi-latest as builder

# Copy netcap source
WORKDIR /netcap
COPY . .

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
        -X github.com/dreadl0ck/netcap/dpi.NDPIVersion=4.14.0 \
        -X github.com/dreadl0ck/netcap/dpi.LibprotoidentVersion=2.0.15-1 \
        -X github.com/dreadl0ck/netcap/dpi.GoDPIVersion=${GO_DPI_VERSION}" \
    -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd

FROM --platform=linux/amd64 ubuntu:24.10
ARG IPV6_SUPPORT=true

RUN apt-get update
RUN apt install -y --fix-missing libpcap0.8 software-properties-common ca-certificates liblzo2-2 libkeyutils-dev tcpdump curl xz-utils
RUN update-ca-certificates

# Install Google Magika CLI v1.0.2 for AI-based file type classification
ARG MAGIKA_VERSION=1.0.2
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then MAGIKA_ARCH="x86_64-unknown-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ]; then MAGIKA_ARCH="aarch64-unknown-linux-gnu"; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    mkdir -p /tmp/magika && \
    curl -LsSf "https://github.com/google/magika/releases/download/cli%2Fv${MAGIKA_VERSION}/magika-${MAGIKA_ARCH}.tar.xz" \
    | tar -xJ -C /tmp/magika && \
    cp /tmp/magika/*/magika /usr/local/bin/magika && \
    chmod +x /usr/local/bin/magika && \
    rm -rf /tmp/magika

WORKDIR /netcap

COPY --from=builder /netcap/bin/* /usr/bin/
COPY --from=builder /usr/lib/libflow* /usr/lib/
COPY --from=builder /usr/lib/libproto* /usr/lib/
COPY --from=builder /usr/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu
COPY --from=builder /usr/local/lib/* /usr/lib/
COPY --from=builder /usr/lib/libndpi* /usr/lib/

CMD ["/bin/sh"]
