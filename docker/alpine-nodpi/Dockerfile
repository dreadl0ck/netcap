FROM --platform=linux/amd64 golang:1.25.1-alpine as builder
RUN apk update
RUN apk add --no-cache gcc libpcap-dev libnetfilter_queue-dev linux-headers musl-utils musl-dev git vim autoconf automake libtool make g++ bison flex cmake build-base abuild binutils binutils-doc gcc-doc cmake-doc extra-cmake-modules extra-cmake-modules-doc

WORKDIR /netcap
COPY . .
RUN go mod download
ENV VERSION XXX
ARG TAGS
RUN echo "tags: $TAGS"

RUN echo go build -mod=readonly ${TAGS} -ldflags "-r /usr/local/lib -s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd
# Disable CGO for nodpi build and reduce compiler memory usage
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -p 1 -mod=readonly ${TAGS} -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd

RUN ls -la /netcap
RUN file /netcap/bin/net

FROM --platform=linux/amd64 alpine:latest
ARG IPV6_SUPPORT=true
RUN apk add --no-cache ca-certificates iptables libpcap-dev libnetfilter_queue ${IPV6_SUPPORT:+ip6tables}
WORKDIR /
COPY --from=builder /netcap/bin/* /usr/bin/
COPY --from=builder /usr/lib/* /usr/lib/
COPY --from=builder /usr/local/lib/* /usr/local/lib/

