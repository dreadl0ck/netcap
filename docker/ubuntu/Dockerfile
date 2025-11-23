FROM --platform=linux/amd64 dreadl0ck/netcap-builder:ubuntu-dpi-latest as builder

# Copy netcap source
WORKDIR /netcap
COPY . .

ENV VERSION XXX

ARG TAGS
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
    GOOS=linux GOARCH=amd64 go build ${TAGS} \
    -ldflags "-s -w \
        -X github.com/dreadl0ck/netcap.Version=v${VERSION} \
        -X github.com/dreadl0ck/netcap.GopacketVersion=${GOPACKET_VERSION} \
        -X github.com/dreadl0ck/netcap/dpi.NDPIVersion=4.14.0 \
        -X github.com/dreadl0ck/netcap/dpi.LibprotoidentVersion=2.0.15-1 \
        -X github.com/dreadl0ck/netcap/dpi.GoDPIVersion=${GO_DPI_VERSION}" \
    -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd

FROM --platform=linux/amd64 ubuntu:24.04
ARG IPV6_SUPPORT=true

RUN apt-get update
RUN apt install -y --fix-missing libpcap0.8 software-properties-common ca-certificates liblzo2-2 libkeyutils-dev tcpdump
RUN update-ca-certificates

WORKDIR /netcap

COPY --from=builder /netcap/bin/* /usr/bin/
COPY --from=builder /usr/lib/libflow* /usr/lib/
COPY --from=builder /usr/lib/libproto* /usr/lib/
COPY --from=builder /usr/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu
COPY --from=builder /usr/local/lib/* /usr/lib/
COPY --from=builder /usr/lib/libndpi* /usr/lib/

CMD ["/bin/sh"]
