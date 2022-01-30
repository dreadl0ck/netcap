FROM golang:1.17.6-alpine as builder
RUN apk update
RUN apk add --no-cache gcc libpcap-dev libnetfilter_queue-dev linux-headers musl-utils musl-dev git vim autoconf automake libtool make g++ bison flex cmake build-base abuild binutils binutils-doc gcc-doc cmake-doc extra-cmake-modules extra-cmake-modules-doc

RUN wget https://github.com/wanduow/wandio/archive/4.2.3-1.tar.gz
RUN tar xfz 4.2.3-1.tar.gz
RUN cd wandio-4.2.3-1 && ./bootstrap.sh && ./configure && make && make install

RUN wget https://github.com/LibtraceTeam/libtrace/archive/4.0.17-1.tar.gz
RUN tar xfz 4.0.17-1.tar.gz
RUN cd libtrace-4.0.17-1 && ./bootstrap.sh && ./configure && make && make install

RUN wget https://github.com/wanduow/libflowmanager/archive/3.0.0.tar.gz
RUN tar xfz 3.0.0.tar.gz
RUN cd libflowmanager-3.0.0 && ./bootstrap.sh && ./configure && make && make install

RUN wget https://github.com/wanduow/libprotoident/archive/2.0.15-1.tar.gz
RUN tar xfz 2.0.15-1.tar.gz
RUN cd libprotoident-2.0.15-1 && ./bootstrap.sh && ./configure && make && make install

# debug linker search path: ld -llinear --verbose
#RUN git clone https://github.com/cjlin1/liblinear.git
#RUN cd liblinear && make && cp linear.h /usr/local/include && cp linear.o /usr/local/lib && mkdir -p /usr/local/lib/liblinear && cp linear.o /usr/lib/liblinear.o

# nDPI
RUN apk add json-c-dev
RUN wget https://github.com/ntop/nDPI/archive/4.0.tar.gz
RUN tar xfz 4.0.tar.gz
RUN cd nDPI-4.0 && ./autogen.sh && ./configure && make && make install

WORKDIR /netcap
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV VERSION XXX
ARG tags
ENV TAGS $tags
RUN echo "tags: $TAGS"

ENV CFLAGS -I/usr/local/lib
ENV CPPFLAGS -I/usr/local/lib
ENV CXXFLAGS -I/usr/local/lib
ENV LDFLAGS --verbose -v -L/usr/local/lib -llinear -ltrace -lndpi -lpcap -lm -pthread

ENV LD_LIBRARY_PATH /usr/local/lib:/usr/lib:/go
ENV LD_RUN_PATH /usr/local/lib

#ENV LD_DEBUG libs
#ENV LD_DEBUG=all

RUN ldconfig /usr/local/lib/*
RUN ldconfig /go/*

#RUN env
#RUN find / -iname ndpi_main.h
#RUN find / -iname libprotoident.h
#RUN find / -iname libprotoident.o
#RUN find / -iname libtrace.h
#RUN find / -iname libtrace.o
#RUN find / -iname liblinear.o

RUN go build -mod=readonly ${TAGS} -ldflags "-r /usr/local/lib -s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd

RUN ls -la /netcap
RUN file /netcap/bin/net

FROM alpine:latest
ARG IPV6_SUPPORT=true

RUN apk add --no-cache ca-certificates iptables libpcap-dev libnetfilter_queue ${IPV6_SUPPORT:+ip6tables}

WORKDIR /

COPY --from=builder /netcap/bin/* /usr/bin/
COPY --from=builder /usr/lib/* /usr/lib/
COPY --from=builder /usr/local/lib/* /usr/local/lib/

