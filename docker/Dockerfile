# Lets use the latest debian image from the go authors
FROM golang:stretch

# make sure packet lists are up to date
RUN apt-get update

# use this to search for available libs
# RUN apt-cache search libpcap

# install libpcap
RUN apt-get install -y libpcap-dev

RUN echo "working dir: $(pwd)"

# get the NETCAP source
RUN go get -v -u github.com/dreadl0ck/netcap/...

# build all the things.
RUN go build -o netcap -i github.com/dreadl0ck/netcap/cmd
RUN go build -o netlabel -i github.com/dreadl0ck/netcap/label/cmd
RUN go build -o netcap-sensor -i github.com/dreadl0ck/netcap/sensor
RUN go build -o netcap-server -i github.com/dreadl0ck/netcap/server