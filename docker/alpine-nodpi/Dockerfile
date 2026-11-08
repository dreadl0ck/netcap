ARG NETCAP_BUILDER_IMAGE=docker.io/dreadl0ck/netcap-builder:alpine-yara1.22.0-84980998-20261108@sha256:28609aba3e542885acd228eec8ab7cf2a2291a90e42f80f600e27edada09a24b
FROM --platform=linux/amd64 ${NETCAP_BUILDER_IMAGE} AS builder
RUN pkg-config --exact-version=1.22.0 yara_x_capi

# Copy netcap source
WORKDIR /netcap
COPY . .
COPY --from=netcap-webui / /netcap/cmd/capture/webui/frontend/dist/

ENV VERSION XXX
ARG TAGS="-tags nodpi,noyara"
RUN echo "tags: $TAGS"

# Extract gopacket version from go.mod
RUN GOPACKET_VERSION=$(go list -m -f '{{.Version}}{{with .Replace}}+{{.Version}}{{end}}' github.com/gopacket/gopacket) && \
    echo go build ${TAGS} -trimpath -ldflags "-r /usr/local/lib -s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION} -X github.com/dreadl0ck/netcap.GopacketVersion=${GOPACKET_VERSION}" -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd/net && \
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build ${TAGS} -trimpath \
    -ldflags "-s -w \
        -X github.com/dreadl0ck/netcap.Version=v${VERSION} \
        -X github.com/dreadl0ck/netcap.GopacketVersion=${GOPACKET_VERSION}" \
    -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd/net

RUN ls -la /netcap
RUN file /netcap/bin/net

FROM --platform=linux/amd64 alpine:3.24.4@sha256:93b41ef40b1677fce8fcc64ff4af09daddfacf5040afde618bc46c1e2d1cc7d4
ARG IPV6_SUPPORT=true
RUN apk add --no-cache ca-certificates iptables libpcap libnetfilter_queue tcpdump curl gcompat libgcc ${IPV6_SUPPORT:+ip6tables}

# Install Google Magika CLI v1.0.2 for AI-based file type classification
ARG MAGIKA_VERSION=1.0.2
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then MAGIKA_ARCH="x86_64-unknown-linux-gnu"; MAGIKA_SHA256=4ce475c965cd20e724b5fc53e8a303a479b9d8649beef8721d05e9b3988fbab4; \
    elif [ "$ARCH" = "aarch64" ]; then MAGIKA_ARCH="aarch64-unknown-linux-gnu"; MAGIKA_SHA256=55eda0c5dc9e1853ba530000815cd084c1dc654c59d52da486159b907dc9ec84; \
    else echo "Unsupported arch: $ARCH" && exit 1; fi && \
    mkdir -p /tmp/magika && \
    curl -LsSf "https://github.com/google/magika/releases/download/cli/v${MAGIKA_VERSION}/magika-${MAGIKA_ARCH}.tar.xz" -o /tmp/magika.tar.xz && \
    echo "$MAGIKA_SHA256  /tmp/magika.tar.xz" | sha256sum -c - && \
    tar -xJf /tmp/magika.tar.xz -C /tmp/magika && \
    cp /tmp/magika/*/magika /usr/local/bin/magika && \
    chmod +x /usr/local/bin/magika && \
    rm -rf /tmp/magika /tmp/magika.tar.xz

WORKDIR /
COPY --from=builder /netcap/bin/* /usr/bin/
COPY --from=builder /netcap/LICENSE /usr/share/licenses/netcap/LICENSE
COPY --from=builder /netcap/legal /usr/share/licenses/netcap/
COPY --from=builder /usr/local/lib/libyara_x_capi.so /usr/local/lib/
