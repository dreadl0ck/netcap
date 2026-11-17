#!/bin/bash -e

## Clone and compile DPI dependencies from source

sudo apt update
sudo apt install -y libpcap-dev software-properties-common ca-certificates liblzo2-2 libkeyutils-dev
sudo update-ca-certificates
sudo apt-get install -y apt-transport-https curl lsb-release wget autogen autoconf libtool gcc libpcap-dev linux-headers-generic git vim automake libtool make g++ bison flex cmake binutils binutils-doc gcc-doc cmake-doc extra-cmake-modules autoconf pkg-config libconfig-dev

bash scripts/install-debian-dpi.sh

sudo apt install -y liblinear-dev

go mod download

export CFLAGS="-I/usr/local/lib"
export CPPFLAGS="-I/usr/local/lib"
export CXXFLAGS="-I/usr/local/lib"
export LDFLAGS="--verbose -v -L/usr/local/lib -llinear -ltrace -lndpi -lpcap -lm -pthread"
export LD_LIBRARY_PATH="/usr/local/lib:/usr/lib:/go"
export LD_RUN_PATH="/usr/local/lib"

sudo ldconfig

# ensure the go compiler can output the binary to /usr/local/bin
sudo chown -R "$USER" /usr/local/bin

# Extract gopacket version from go.mod
GOPACKET_VERSION=$(go list -m -f '{{.Version}}{{with .Replace}}+{{.Version}}{{end}}' github.com/gopacket/gopacket)

go build -trimpath -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION} -X github.com/dreadl0ck/netcap.GopacketVersion=${GOPACKET_VERSION}" -o /usr/local/bin/net github.com/dreadl0ck/netcap/cmd/net
