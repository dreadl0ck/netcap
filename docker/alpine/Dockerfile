FROM --platform=linux/amd64 dreadl0ck/netcap-builder:alpine-dpi-latest as builder

# Copy netcap source
WORKDIR /netcap
COPY . .

ENV VERSION XXX
ARG TAGS="-tags noyara"
RUN echo "tags: $TAGS"

# Extract library versions from go.mod
RUN GOPACKET_VERSION=$(grep "github.com/gopacket/gopacket" /netcap/go.mod | grep -v indirect | awk '{print $2}') && \
    GO_DPI_VERSION=$(grep "github.com/dreadl0ck/go-dpi" /netcap/go.mod | grep -v indirect | awk '{print $2}') && \
    GOOS=linux GOARCH=amd64 go build ${TAGS} -trimpath \
    -ldflags "-r /usr/local/lib -s -w \
        -X github.com/dreadl0ck/netcap.Version=v${VERSION} \
        -X github.com/dreadl0ck/netcap.GopacketVersion=${GOPACKET_VERSION} \
        -X github.com/dreadl0ck/netcap/dpi.NDPIVersion=4.14.0 \
        -X github.com/dreadl0ck/netcap/dpi.LibprotoidentVersion=2.0.15-1 \
        -X github.com/dreadl0ck/netcap/dpi.GoDPIVersion=${GO_DPI_VERSION}" \
    -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd

RUN ls -la /netcap
RUN file /netcap/bin/net

FROM --platform=linux/amd64 alpine:latest
ARG IPV6_SUPPORT=true

RUN apk add --no-cache ca-certificates iptables libpcap libnetfilter_queue tcpdump curl gcompat ${IPV6_SUPPORT:+ip6tables}

# Install Google Magika CLI v1.0.2 for AI-based file type classification
ARG MAGIKA_VERSION=1.0.2
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then MAGIKA_ARCH="x86_64-unknown-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ]; then MAGIKA_ARCH="aarch64-unknown-linux-gnu"; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    curl -LsSf "https://github.com/google/magika/releases/download/cli%2Fv${MAGIKA_VERSION}/magika-${MAGIKA_ARCH}.tar.xz" \
    | tar -xJ -C /usr/local/bin/ && \
    chmod +x /usr/local/bin/magika

WORKDIR /

COPY --from=builder /netcap/bin/* /usr/bin/
COPY --from=builder /usr/lib/* /usr/lib/
COPY --from=builder /usr/local/lib/* /usr/local/lib/

