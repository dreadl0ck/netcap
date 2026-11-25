# Netcap Try Service - Alpine Linux
# Container for running the try service with file upload capabilities (with DPI support)

ARG NETCAP_BUILDER_IMAGE=docker.io/dreadl0ck/netcap-builder:alpine-dpi-yara1.22.0-84980998-20261108@sha256:eb0472fc0b30b11c4482cf458c1727881eef2938f569c50ce15afdc1c660e779
# Frontend stage - build the web UI from source.
#
# cmd/capture/webui/embed.go does `//go:embed all:frontend/dist`, so the Go build
# below cannot even compile without this directory. It used to be supplied by
# whatever dist/ happened to exist on the machine running the build, which is
# gitignored -- so the published image was not reproducible from this repo, and a
# rebuild silently shipped a different bundle than the one it replaced. That is
# how a getBackendUrl() default of http://localhost:8080 reached production and
# hung the app on "connecting to backend": the deployed bundle had been built by
# hand months earlier with VITE_BACKEND_URL set, and nothing else ever exercised
# the fallback.
#
# Building it here makes git the single source of truth. .dockerignore excludes
# cmd/capture/webui/frontend/dist so a stale local bundle cannot enter the
# context and win over this stage.
#
# $BUILDPLATFORM rather than linux/amd64: the output is platform-independent
# JavaScript, so this runs natively on the builder instead of under emulation.
FROM --platform=$BUILDPLATFORM node:22-alpine3.24@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202 AS frontend

WORKDIR /frontend
ENV GOMAXPROCS=4

# pnpm 9.15.0 is what package.json declares and what wrote pnpm-lock.yaml
# (lockfileVersion 9.0). Pinning it keeps --frozen-lockfile meaningful.
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate

# Manifests first, so the dependency layer is reused when only source changes.
COPY cmd/capture/webui/frontend/package.json \
     cmd/capture/webui/frontend/pnpm-lock.yaml \
     cmd/capture/webui/frontend/pnpm-workspace.yaml ./
COPY cmd/capture/webui/frontend/packages/netcap-ui/package.json packages/netcap-ui/
COPY LICENSE /netcap-legal/LICENSE
COPY legal/ /netcap-legal/legal/

RUN pnpm install --frozen-lockfile

COPY cmd/capture/webui/frontend/ ./
ENV NETCAP_ROOT=/netcap-legal

# Builds packages/netcap-ui with tsup, then the app with vite.
RUN pnpm build && test -f dist/index.html

# Build stage - Use official netcap builder with DPI support
FROM --platform=linux/amd64 ${NETCAP_BUILDER_IMAGE} AS builder
RUN pkg-config --exact-version=1.22.0 yara_x_capi

# Copy netcap source
WORKDIR /netcap
COPY . .

# The web UI built above, placed where go:embed expects it. Must come after
# COPY . . so it cannot be overwritten by anything from the build context.
COPY --from=frontend /frontend/dist ./cmd/capture/webui/frontend/dist

# Regenerate types/netcap.pb.go from types/netcap.proto so the image cannot
# embed types that disagree with the schema. The file is tracked since 3dbcc508
# and no .dockerignore excludes it, so it does reach the build context -- this
# step overwrites it deterministically rather than rescuing its absence.
#
# --proto_path=types is load-bearing: without it protoc writes
# types/proto/netcap.pb.go, leaving the real types/netcap.pb.go untouched, and
# the `test -s` below would still pass.
#
# protoc and protoc-gen-gogofaster come from the builder image, pinned to the
# gogo/protobuf release in go.mod so the generated code matches its runtime.
RUN protoc --proto_path=types --gogofaster_out=types/. types/netcap.proto && test -s types/netcap.pb.go

# Accept VERSION as a build argument (defaults to 0.7.7 if not provided)
ARG VERSION=0.7.7
ARG COMMIT

ARG NETCAP_BUILDER_IMAGE

# Remove any existing binary
RUN rm -rf /netcap/bin

# Build the binary WITH DPI support (disable workspace mode)
# Extract library versions from go.mod
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build,id=go-${NETCAP_BUILDER_IMAGE} \
    GOPACKET_VERSION=$(go list -m -f '{{.Version}}{{with .Replace}}+{{.Version}}{{end}}' github.com/gopacket/gopacket) && \
    GO_DPI_VERSION=$(grep "github.com/dreadl0ck/go-dpi" /netcap/go.mod | grep -v indirect | awk '{print $2}') && \
    mkdir -p /netcap/bin && \
    GOWORK=off GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
    -ldflags "-r /usr/local/lib -s -w \
        -X github.com/dreadl0ck/netcap.Version=v${VERSION} \
        -X github.com/dreadl0ck/netcap.Commit=${COMMIT} \
        -X github.com/dreadl0ck/netcap.GopacketVersion=${GOPACKET_VERSION} \
        -X github.com/dreadl0ck/netcap/internal/dpi.NDPIVersion=4.14.0 \
        -X github.com/dreadl0ck/netcap/internal/dpi.LibprotoidentVersion=2.0.15-1 \
        -X github.com/dreadl0ck/netcap/internal/dpi.GoDPIVersion=${GO_DPI_VERSION}" \
    -o /netcap/bin/netcap github.com/dreadl0ck/netcap/cmd/net

# Runtime stage
FROM --platform=linux/amd64 alpine:3.24.4@sha256:93b41ef40b1677fce8fcc64ff4af09daddfacf5040afde618bc46c1e2d1cc7d4 AS os-runtime

LABEL maintainer="Philipp Mieden <dreadl0ck@protonmail.ch>"
LABEL description="Netcap Service Mode - Upload and analyze PCAP files (with DPI support)"

# Install runtime dependencies including DPI libraries
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    libpcap \
    tcpdump \
    libcap \
    iptables \
    libnetfilter_queue \
    libstdc++ \
    libgcc \
    json-c

FROM builder AS service-binaries
ARG NETCAP_RELEASE_HYGIENE=0
RUN apk add --no-cache binutils python3
RUN --mount=from=os-runtime,target=/runtime \
    mkdir -p /shipped/usr/local/bin /shipped/usr/local/lib /shipped/usr/lib && \
    cp /netcap/bin/netcap /shipped/usr/local/bin/net && \
    cp -a /usr/local/lib/*.so* /shipped/usr/local/lib/ && \
    cp -a /usr/lib/libndpi.so* /shipped/usr/lib/ && \
    cp -L /runtime/usr/lib/libstdc++.so.6 /shipped/usr/lib/libstdc++.so.6 && \
    if [ "$NETCAP_RELEASE_HYGIENE" = 1 ]; then \
        python3 scripts/strip-linux-runtime.py --debug-dir /debug /shipped/usr/local/lib /shipped/usr/lib && \
        python3 scripts/check-binary-hygiene.py /shipped; \
    fi

FROM os-runtime AS service

# Give tcpdump the necessary capabilities to read pcap files without root
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump

# Create netcap user and group (non-root)
RUN addgroup -g 1000 netcap && \
    adduser -D -u 1000 -G netcap netcap

# Set working directory
WORKDIR /home/netcap

# Copy binary and DPI libraries from builder
COPY --from=service-binaries /shipped/ /
COPY --from=builder /netcap/LICENSE /usr/share/licenses/netcap/LICENSE
COPY --from=builder /netcap/legal /usr/share/licenses/netcap/

# Run ldconfig to register the shared libraries and set up the dynamic linker cache
RUN ldconfig /usr/lib /usr/local/lib || true

# Set LD_LIBRARY_PATH to ensure runtime linker finds nDPI and other DPI libraries
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib

# Copy entrypoint script
COPY docker/service/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Create data directories with proper permissions
RUN mkdir -p /data/netcap-service && \
    mkdir -p /home/netcap/.config/netcap && \
    chown -R netcap:netcap /data /home/netcap

# Switch to netcap user (non-root)
USER netcap

# Expose HTTP port
EXPOSE 7070

# Health check
# HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
#     CMD curl -f http://localhost:7070/health || exit 1

# Set environment variables
ENV NC_DATA_DIR=/data/netcap-service
ENV NC_HTTP=0.0.0.0:7070

# Volume for persistent data
VOLUME ["/data"]

# Use entrypoint script to bootstrap databases
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

FROM --platform=linux/amd64 alpine:3.24.4@sha256:93b41ef40b1677fce8fcc64ff4af09daddfacf5040afde618bc46c1e2d1cc7d4 AS showcase-magika-archive
ADD --checksum=sha256:4ce475c965cd20e724b5fc53e8a303a479b9d8649beef8721d05e9b3988fbab4 https://github.com/google/magika/releases/download/cli/v1.0.2/magika-x86_64-unknown-linux-gnu.tar.xz /tmp/magika.tar.xz
RUN mkdir /magika && tar -xJOf /tmp/magika.tar.xz magika-x86_64-unknown-linux-gnu/magika > /magika/magika && \
    chmod 0755 /magika/magika

FROM --platform=linux/amd64 ubuntu:24.04@sha256:9a04f13b3f80ef056361e30868593b1cfd2279fe19e4081cb93a90bf56819d6a AS showcase-magika
COPY --from=showcase-magika-archive /magika/ /magika/
COPY scripts/strip-linux-runtime.py scripts/check-binary-hygiene.py /tmp/
RUN apt-get update && apt-get install -y --no-install-recommends binutils python3
RUN cp -L /lib64/ld-linux-x86-64.so.2 /magika/ && \
    ldd /magika/magika | awk '/=> \/lib\// {print $3}' | xargs -r cp -L -t /magika && \
    cp /usr/share/doc/libc6/copyright /magika/glibc-copyright && \
    python3 /tmp/strip-linux-runtime.py --debug-dir /debug /magika && \
    python3 /tmp/check-binary-hygiene.py /magika && \
    /magika/ld-linux-x86-64.so.2 --library-path /magika /magika/magika --version

# Build with --target showcase --build-context showcase_enrichment=PATH.
FROM service AS showcase
USER root
COPY --from=showcase-magika /magika/ /opt/netcap/magika/
COPY docker/service/magika-wrapper.sh /usr/local/bin/magika
RUN chmod 0755 /usr/local/bin/magika && magika --version
COPY --from=showcase_enrichment --chown=1000:1000 / /opt/netcap/enrichment/
COPY docker/service/showcase-files.yml /opt/netcap/showcase-files.yml
COPY docker/service/showcase.yar /opt/netcap/showcase-rules/format.yar
ENV NC_ENRICHMENT_ROOT=/opt/netcap/enrichment
ENV NC_SHOWCASE_FILE_CONFIG=/opt/netcap/showcase-files.yml
USER netcap

FROM service AS runtime
