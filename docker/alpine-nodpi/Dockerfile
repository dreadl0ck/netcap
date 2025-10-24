FROM --platform=linux/amd64 dreadl0ck/netcap-builder:alpine-latest as builder

# Copy netcap source
WORKDIR /netcap
COPY . .

ENV VERSION XXX
ARG TAGS
RUN echo "tags: $TAGS"

RUN echo go build ${TAGS} -ldflags "-r /usr/local/lib -s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd
# CGO is still required for libpcap support even without DPI
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build ${TAGS} -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd

RUN ls -la /netcap
RUN file /netcap/bin/net

FROM --platform=linux/amd64 alpine:latest
ARG IPV6_SUPPORT=true
RUN apk add --no-cache ca-certificates iptables libpcap libnetfilter_queue ${IPV6_SUPPORT:+ip6tables}
WORKDIR /
COPY --from=builder /netcap/bin/* /usr/bin/
COPY --from=builder /usr/lib/* /usr/lib/
COPY --from=builder /usr/local/lib/* /usr/local/lib/

