# syntax=docker/dockerfile:1
FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
ENV GOWORK=off CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -tags coraza -trimpath -buildvcs=false -ldflags='-s -w' -o /out/netcap-firewall ./cmd/netcap-firewall
RUN mkdir -p /out/legal/licenses && cp LICENSE /out/LICENSE && cp legal/*.txt /out/legal/ && \
    cp docker/firewall/THIRD_PARTY_NOTICES.txt /out/legal/FIREWALL_NOTICES.txt && \
    go version -m /out/netcap-firewall > /out/legal/BUILD_MODULES.txt && \
    go list -m -f '{{if .Dir}}{{.Path}} {{.Dir}}{{end}}' all | while read -r module dir; do \
      [ -n "$dir" ] || continue; \
      dest="/out/legal/licenses/$module"; \
      for notice in "$dir"/LICENSE* "$dir"/NOTICE* "$dir"/COPYING*; do \
        [ -f "$notice" ] || continue; mkdir -p "$dest"; cp "$notice" "$dest/"; \
      done; \
    done

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/netcap-firewall /netcap-firewall
COPY --from=build /out/LICENSE /LICENSE
COPY --from=build /out/legal /legal
USER 10001:10001
EXPOSE 8080 9090
ENTRYPOINT ["/netcap-firewall"]
CMD ["serve", "--config", "/etc/netcap-firewall/config.yaml"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 CMD ["/netcap-firewall", "healthcheck", "--url", "http://127.0.0.1:9090/readyz"]
