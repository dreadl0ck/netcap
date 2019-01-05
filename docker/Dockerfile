FROM golang:stretch

RUN apt-get update
#RUN apt-cache search libpcap
RUN apt-get install -y libpcap-dev
RUN echo "pwd:$(pwd)"
RUN go get -v -u github.com/dreadl0ck/netcap/...
RUN go build -o nc-linux -i github.com/dreadl0ck/netcap/cmd

# run container
# docker build .

# get container id
# docker ps -a

# extract binary from container
# docker cp {CONTAINER_ID}:/go/nc-linux .
