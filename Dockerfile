FROM golang:1.14-alpine as builder
RUN apk update
RUN apk add --no-cache gcc libpcap-dev libnetfilter_queue-dev linux-headers musl-utils musl-dev git vim autoconf automake libtool make g++ bison flex cmake build-base abuild binutils binutils-doc gcc-doc cmake-doc extra-cmake-modules extra-cmake-modules-doc

RUN wget https://github.com/wanduow/wandio/archive/4.2.2-1.tar.gz
RUN tar xfz 4.2.2-1.tar.gz
RUN cd wandio-4.2.2-1 && ./bootstrap.sh && ./configure && make && make install

RUN wget https://github.com/LibtraceTeam/libtrace/archive/4.0.11-1.tar.gz
RUN tar xfz 4.0.11-1.tar.gz
RUN cd libtrace-4.0.11-1 && ./bootstrap.sh && ./configure && make && make install

RUN wget https://github.com/wanduow/libflowmanager/archive/3.0.0.tar.gz
RUN tar xfz 3.0.0.tar.gz
RUN cd libflowmanager-3.0.0 && ./bootstrap.sh && ./configure && make && make install

RUN wget https://github.com/wanduow/libprotoident/archive/2.0.14-1.tar.gz
RUN tar xfz 2.0.14-1.tar.gz
RUN cd libprotoident-2.0.14-1 && ./bootstrap.sh && ./configure && make && make install

RUN git clone https://github.com/cjlin1/liblinear.git
RUN cd liblinear && make && cp linear.h /usr/local/include && cp linear.o /usr/local/lib && mkdir -p /usr/local/lib/liblinear && cp linear.o /usr/local/lib/liblinear

# nDPI
RUN wget https://github.com/ntop/nDPI/archive/3.0.tar.gz
RUN tar xfz 3.0.tar.gz
RUN cd nDPI-3.0 && ./autogen.sh && ./configure && make && make install

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV VERSION "0.4.8"

ENV CFLAGS -I/usr/local/lib
ENV CPPFLAGS -I/usr/local/lib
ENV CXXFLAGS -I/usr/local/lib
ENV LDFLAGS --verbose -v -L/usr/local/lib -llinear -ltrace -lndpi -lpcap -lm -pthread

ENV LD_LIBRARY_PATH /usr/local/lib:/usr/lib:/go
ENV LD_RUN_PATH /usr/local/lib
ENV LD_DEBUG libs

RUN ldconfig /usr/local/lib/*
RUN ldconfig /go/*

RUN env
RUN find / -iname ndpi_main.h
RUN find / -iname libprotoident.h
RUN find / -iname libprotoident.o
RUN find / -iname libtrace.h
RUN find / -iname libtrace.o
RUN find / -iname linear.h
RUN find / -iname linear.o

# -linkshared ?
RUN go build -v -x -mod=readonly -ldflags "-v -r /usr/local/lib -s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/net.capture -i github.com/dreadl0ck/netcap/cmd/capture
RUN echo YESSS
RUN exit 1

RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/net.label -i github.com/dreadl0ck/netcap/cmd/label
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/net.collect -i github.com/dreadl0ck/netcap/cmd/collect
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/net.agent -i github.com/dreadl0ck/netcap/cmd/agent
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/net.proxy -i github.com/dreadl0ck/netcap/cmd/proxy
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/net.export -i github.com/dreadl0ck/netcap/cmd/export
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/net.dump -i github.com/dreadl0ck/netcap/cmd/dump
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/net.util -i github.com/dreadl0ck/netcap/cmd/util

RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetApplications -i github.com/dreadl0ck/netcap/cmd/maltego/GetApplications
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetDNSQuestions -i github.com/dreadl0ck/netcap/cmd/maltego/GetDNSQuestions
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetDeviceContacts -i github.com/dreadl0ck/netcap/cmd/maltego/GetDeviceContacts
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetDeviceIPs -i github.com/dreadl0ck/netcap/cmd/maltego/GetDeviceIPs
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetDeviceProfiles -i github.com/dreadl0ck/netcap/cmd/maltego/GetDeviceProfiles
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetDevices -i github.com/dreadl0ck/netcap/cmd/maltego/GetDevices
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetDstPorts -i github.com/dreadl0ck/netcap/cmd/maltego/GetDstPorts
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetGeolocation -i github.com/dreadl0ck/netcap/cmd/maltego/GetGeolocation
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetHTTPContentTypes -i github.com/dreadl0ck/netcap/cmd/maltego/GetHTTPContentTypes
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetHTTPHosts -i github.com/dreadl0ck/netcap/cmd/maltego/GetHTTPHosts
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetHTTPServerNames -i github.com/dreadl0ck/netcap/cmd/maltego/GetHTTPServerNames
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetHTTPStatusCodes -i github.com/dreadl0ck/netcap/cmd/maltego/GetHTTPStatusCodes
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetHTTPURLs -i github.com/dreadl0ck/netcap/cmd/maltego/GetHTTPURLs
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetHTTPUserAgents -i github.com/dreadl0ck/netcap/cmd/maltego/GetHTTPUserAgents
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetSNIs -i github.com/dreadl0ck/netcap/cmd/maltego/GetSNIs
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/GetSrcPorts -i github.com/dreadl0ck/netcap/cmd/maltego/GetSrcPorts

FROM alpine:3.10.2
ARG IPV6_SUPPORT=true
RUN apk add --no-cache ca-certificates iptables libpcap-dev libnetfilter_queue ${IPV6_SUPPORT:+ip6tables}
WORKDIR /netcap
COPY --from=builder /netcap .
RUN ls -la
CMD ["/bin/ash"]
