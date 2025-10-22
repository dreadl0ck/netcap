FROM --platform=linux/amd64 ubuntu:18.04 as builder
RUN apt-get clean
RUN apt-get update
RUN apt-get install -y software-properties-common wget

# Install Go 1.25.1 manually
RUN wget https://go.dev/dl/go1.25.1.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.25.1.linux-amd64.tar.gz && \
    rm go1.25.1.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
RUN apt-get install -y apt-transport-https curl lsb-release wget autogen autoconf libtool gcc libpcap-dev linux-headers-generic git vim

WORKDIR /src
COPY . .
RUN go mod download
ENV VERSION XXX
ARG TAGS
RUN echo "tags: $TAGS"

RUN echo go build -mod=readonly ${TAGS} -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd
# Disable CGO for nodpi build and reduce compiler memory usage
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -p 1 -mod=readonly ${TAGS} -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd

#RUN ls -la /usr/lib/

FROM --platform=linux/amd64 ubuntu:18.04
ARG IPV6_SUPPORT=true
RUN apt-get update
RUN apt install -y --fix-missing libpcap-dev software-properties-common ca-certificates liblzo2-2 libkeyutils-dev git-lfs
RUN update-ca-certificates
WORKDIR /netcap
COPY --from=builder /netcap/bin/* /usr/bin/
#COPY --from=builder /usr/lib/* /usr/lib/
COPY --from=builder /usr/local/lib/* /usr/lib/
CMD ["/bin/sh"]
