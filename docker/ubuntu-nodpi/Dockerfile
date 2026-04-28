FROM --platform=linux/amd64 dreadl0ck/netcap-builder:ubuntu-latest as builder

# Copy netcap source
WORKDIR /netcap
COPY . .

ENV VERSION XXX
ARG TAGS="-tags noyara"
RUN echo "tags: $TAGS"

# Extract gopacket version from go.mod
RUN GOPACKET_VERSION=$(grep "github.com/gopacket/gopacket" /netcap/go.mod | grep -v indirect | awk '{print $2}') && \
    echo go build ${TAGS} -trimpath -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION} -X github.com/dreadl0ck/netcap.GopacketVersion=${GOPACKET_VERSION}" -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd && \
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build ${TAGS} -trimpath \
    -ldflags "-s -w \
        -X github.com/dreadl0ck/netcap.Version=v${VERSION} \
        -X github.com/dreadl0ck/netcap.GopacketVersion=${GOPACKET_VERSION}" \
    -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd

#RUN ls -la /usr/lib/

FROM --platform=linux/amd64 ubuntu:24.04
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
#COPY --from=builder /usr/lib/* /usr/lib/
COPY --from=builder /usr/local/lib/* /usr/lib/
CMD ["/bin/sh"]
