FROM ubuntu:18.04 as builder

RUN apt-get clean
RUN apt-get update
RUN apt-get install -y software-properties-common net-tools
RUN add-apt-repository ppa:longsleep/golang-backports
RUN apt-get update
RUN apt-get install -y golang-go

RUN apt-get install -y apt-transport-https curl lsb-release wget autogen autoconf libtool gcc libpcap-dev linux-headers-generic git vim
RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libwandio/cfg/setup/bash.deb.sh' | bash
RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libwandder/cfg/setup/bash.deb.sh' | bash
RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libtrace/cfg/setup/bash.deb.sh' | bash
RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libflowmanager/cfg/setup/bash.deb.sh' | bash
RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libprotoident/cfg/setup/bash.deb.sh' | bash
RUN apt-get update
RUN apt install -y liblinear-dev libprotoident libprotoident-dev libprotoident-tools libtrace4-dev libtrace4-tools

# nDPI
RUN apt-get install -y libjson-c-dev
RUN wget https://github.com/ntop/nDPI/archive/4.0.tar.gz
RUN tar xfz 4.0.tar.gz
RUN cd nDPI-4.0 && ./autogen.sh && ./configure && make && make install

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ENV VERSION XXX

ARG tags
ENV TAGS $tags
RUN echo "tags: $TAGS"

ENV CFLAGS -I/usr/local/include/
ENV LDFLAGS -ltrace -lndpi -lpcap -lm -pthread

# debug info
RUN env
RUN find / -iname ndpi_main.h
RUN find / -iname libprotoident.h
RUN find / -iname libtrace.h
RUN ls /usr/lib/*

# compile
RUN go build -mod=readonly ${TAGS} -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd

FROM ubuntu:18.04
ARG IPV6_SUPPORT=true

RUN apt-get update
RUN apt install -y --fix-missing libpcap-dev software-properties-common ca-certificates liblzo2-2 libkeyutils-dev
RUN update-ca-certificates

WORKDIR /netcap

COPY --from=builder /netcap/bin/* /usr/bin/
COPY --from=builder /usr/lib/libflow* /usr/lib/
COPY --from=builder /usr/lib/libproto* /usr/lib/
COPY --from=builder /usr/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu
COPY --from=builder /usr/local/lib/* /usr/lib/
COPY --from=builder /usr/lib/libndpi* /usr/lib/

CMD ["/bin/sh"]
