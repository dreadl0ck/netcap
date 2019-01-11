FROM golang:1.11-alpine

# install libpcap
RUN apk update && apk add libpcap-dev git build-base && rm -rf /var/cache/apk/*

RUN echo "working dir: $(pwd)"

# get the NETCAP source
RUN go get -v -u github.com/dreadl0ck/netcap/...

# build all the things.
RUN go build -o netcap -i github.com/dreadl0ck/netcap/cmd
RUN go build -o netlabel -i github.com/dreadl0ck/netcap/label/cmd
RUN go build -o netcap-sensor -i github.com/dreadl0ck/netcap/sensor
RUN go build -o netcap-server -i github.com/dreadl0ck/netcap/server
