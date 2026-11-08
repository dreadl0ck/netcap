ARG NETCAP_BUILDER_IMAGE=docker.io/dreadl0ck/netcap-builder:ubuntu-yara1.22.0-84980998-20261108@sha256:c50ccee7fc32abb1e1091cfa1610e457d458a4a36a25b237728ce24eaac27efd
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
    echo go build ${TAGS} -trimpath -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION} -X github.com/dreadl0ck/netcap.GopacketVersion=${GOPACKET_VERSION}" -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd/net && \
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build ${TAGS} -trimpath \
    -ldflags "-s -w \
        -X github.com/dreadl0ck/netcap.Version=v${VERSION} \
        -X github.com/dreadl0ck/netcap.GopacketVersion=${GOPACKET_VERSION}" \
    -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd/net

#RUN ls -la /usr/lib/

FROM --platform=linux/amd64 ubuntu:26.04
ARG IPV6_SUPPORT=true
RUN apt-get update
RUN apt install -y --fix-missing libpcap0.8 software-properties-common ca-certificates liblzo2-2 libkeyutils-dev tcpdump curl xz-utils
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
COPY --from=builder /usr/local/lib/libyara_x_capi.so /usr/local/lib/
CMD ["/bin/sh"]
