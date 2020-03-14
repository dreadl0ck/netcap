FROM ubuntu:18.04 as builder
RUN apt-get update
RUN apt-get install -y software-properties-common
RUN add-apt-repository ppa:longsleep/golang-backports
RUN apt-get update
RUN apt-get install -y golang-go
RUN apt install -y gcc libpcap-dev linux-headers-generic git vim
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV VERSION "0.4.5"
RUN go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/net.capture -i github.com/dreadl0ck/netcap/cmd/capture
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

FROM ubuntu:18.04
ARG IPV6_SUPPORT=true
RUN apt-get update
RUN apt install -y libpcap-dev
#RUN update-ca-certificates
WORKDIR /netcap
COPY --from=builder /netcap .
RUN ls -la
CMD ["/bin/sh"]

