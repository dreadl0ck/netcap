#!/bin/bash -e

## Clone and compile DPI dependencies from source

sudo apt update
sudo apt install -y libpcap-dev software-properties-common ca-certificates liblzo2-2 libkeyutils-dev
sudo update-ca-certificates
sudo apt-get install -y apt-transport-https curl lsb-release wget autogen autoconf libtool gcc libpcap-dev linux-headers-generic git vim automake libtool make g++ bison flex cmake binutils binutils-doc gcc-doc cmake-doc extra-cmake-modules autoconf pkg-config libconfig-dev

wget -qN https://github.com/wanduow/wandio/archive/4.2.2-1.tar.gz
tar xfz 4.2.2-1.tar.gz
cd wandio-4.2.2-1 && ./bootstrap.sh && ./configure && make && sudo make install
cd ..

wget -qN https://github.com/LibtraceTeam/libtrace/archive/4.0.11-1.tar.gz
tar xfz 4.0.11-1.tar.gz
cd libtrace-4.0.11-1 && ./bootstrap.sh && ./configure && make && sudo make install
cd ..

wget -qN https://github.com/wanduow/libflowmanager/archive/3.0.0.tar.gz
tar xfz 3.0.0.tar.gz
cd libflowmanager-3.0.0 && ./bootstrap.sh && ./configure && make && sudo make install
cd ..

wget -qN https://github.com/wanduow/libprotoident/archive/2.0.14-1.tar.gz
tar xfz 2.0.14-1.tar.gz
cd libprotoident-2.0.14-1 && ./bootstrap.sh && ./configure && make && sudo make install
cd ..

wget -qN https://github.com/ntop/nDPI/archive/3.2.tar.gz
tar xfz 3.2.tar.gz
cd nDPI-3.2 && ./autogen.sh && ./configure && make && sudo make install
cd ..

sudo apt install -y liblinear-dev

go mod download

export CFLAGS="-I/usr/local/lib"
export CPPFLAGS="-I/usr/local/lib"
export CXXFLAGS="-I/usr/local/lib"
export LDFLAGS="--verbose -v -L/usr/local/lib -llinear -ltrace -lndpi -lpcap -lm -pthread"
export LD_LIBRARY_PATH="/usr/local/lib:/usr/lib:/go"
export LD_RUN_PATH="/usr/local/lib"

sudo ldconfig /usr/local/lib/*
sudo ldconfig /go/*

# debug info
env
sudo find / -iname ndpi_main.h
sudo find / -iname libprotoident.h
sudo find / -iname libtrace.h

# ensure the go compiler can output the binary to /usr/local/bin
sudo chown -R "$USER" /usr/local/bin

go build -mod=readonly -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /usr/local/bin/net github.com/dreadl0ck/netcap/cmd


