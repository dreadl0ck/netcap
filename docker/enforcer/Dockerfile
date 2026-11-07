# syntax=docker/dockerfile:1
FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
ENV GOWORK=off CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/netcap-firewall ./cmd/netcap-firewall && \
    mkdir -p /out/legal/licenses && cp LICENSE /out/LICENSE && cp legal/*.txt /out/legal/ && \
    go version -m /out/netcap-firewall > /out/legal/BUILD_MODULES.txt && \
    go list -m -f '{{if .Dir}}{{.Path}} {{.Dir}}{{end}}' all | while read -r module dir; do \
      [ -n "$dir" ] || continue; \
      for notice in "$dir"/LICENSE* "$dir"/NOTICE* "$dir"/COPYING*; do \
        [ -f "$notice" ] || continue; mkdir -p "/out/legal/licenses/$module"; cp "$notice" "/out/legal/licenses/$module/"; \
      done; \
    done

FROM alpine:3.23.2@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62 AS runtime
RUN apk add --no-cache iproute2-minimal=6.17.0-r0 nftables=1.1.5-r2 && \
    mkdir -p /var/lib/netcap-enforcer /run/netcap-enforcer && chmod 700 /run/netcap-enforcer && \
    apk info -v > /etc/netcap-enforcer-packages.txt
COPY --from=build /out/netcap-firewall /netcap-firewall
COPY --from=build /out/LICENSE /LICENSE
COPY --from=build /out/legal /legal
COPY docker/enforcer/entrypoint.sh /entrypoint.sh
USER 0:0
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
CMD ["--help"]

FROM build AS test-build
RUN go test -c -tags integration -o /out/enforcer.test ./internal/enforcer && \
    go test -c -o /out/networkfirewall.test ./internal/networkfirewall

FROM runtime AS qualification
COPY --from=test-build /out/enforcer.test /enforcer.test
COPY --from=test-build /out/networkfirewall.test /networkfirewall.test
COPY examples/firewall/enforcer_package.sh /enforcer_package.sh
COPY examples/firewall/network_package.sh /network_package.sh
COPY examples/firewall/network-policy.yaml /network-policy.yaml
ENTRYPOINT ["/enforcer.test"]

FROM runtime AS release
