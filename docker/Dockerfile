FROM golang:1.12.4-alpine

# install libpcap
RUN apk update && apk add libpcap-dev git build-base && rm -rf /var/cache/apk/*

RUN echo "working dir: $(pwd)"

# get the NETCAP source
#RUN go get -v -u github.com/dreadl0ck/netcap/...

RUN mkdir -p $GOPATH/src/github.com/dreadl0ck/netcap
RUN cd $GOPATH/src/github.com/dreadl0ck && git clone https://github.com/dreadl0ck/netcap.git && echo "cloned!" && go get github.com/bradleyfalzon/tlsx && go get ./... && echo "got dependencies!"

RUN echo GOPATH=$GOPATH
RUN ls /go/src/github.com/dreadl0ck/netcap/cmd

# build all the things.
RUN go build -o net.capture -i github.com/dreadl0ck/netcap/cmd/capture
RUN go build -o net.label -i github.com/dreadl0ck/netcap/cmd/label
RUN go build -o net.agent -i github.com/dreadl0ck/netcap/cmd/agent
RUN go build -o net.collect -i github.com/dreadl0ck/netcap/cmd/collect
RUN go build -o net.proxy -i github.com/dreadl0ck/netcap/cmd/proxy
RUN go build -o net.export -i github.com/dreadl0ck/netcap/cmd/export
RUN go build -o net.dump -i github.com/dreadl0ck/netcap/cmd/dump
RUN go build -o net.util -i github.com/dreadl0ck/netcap/cmd/util
