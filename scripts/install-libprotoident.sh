#!/bin/bash

# =============================================================================== #
# Basic libprotoident install script for linux systems and macOS                  #
# Library GitHub: https://github.com/wanduow/libprotoident                        #
# Motivation: the packages distributed via apt or homebrew are often outdated,    #
# this script allows an easy setup of the latest version and its dependencies.    #
# =============================================================================== #

# TODO: test on a fresh install
# - test on debian linux
# - test on alpine linux
# - test on M1 mac
# - test on intel mac

# Libprotoident version to install
VERSION=2.0.15

echo "installing libprotoident v$VERSION"

if [[ $OSTYPE == 'darwin'* ]]; then
  echo 'macOS'
elif [[ $OSTYPE == 'linux-gnu'* ]]; then
  echo 'linux'

  # debian
  #apt-get install -y apt-transport-https curl lsb-release wget autogen autoconf libtool gcc libpcap-dev linux-headers-generic git vim

  # alpine linux
  #apk add --no-cache gcc libpcap-dev libnetfilter_queue-dev linux-headers musl-utils musl-dev git vim autoconf automake libtool make g++ bison flex cmake build-base abuild binutils binutils-doc gcc-doc cmake-doc extra-cmake-modules extra-cmake-modules-doc
fi

# move into a new directory
mkdir -p libprotoident
cd libprotoident || return

# wandio
wget https://github.com/wanduow/wandio/archive/4.2.3-1.tar.gz
tar xfz 4.2.3-1.tar.gz
cd wandio-4.2.3-1 && ./bootstrap.sh && ./configure && make && make install

# libtrace
wget https://github.com/LibtraceTeam/libtrace/archive/4.0.17-1.tar.gz
tar xfz 4.0.17-1.tar.gz
cd libtrace-4.0.17-1 && ./bootstrap.sh && ./configure && make && make install

# libflowmanager
wget https://github.com/wanduow/libflowmanager/archive/3.0.0.tar.gz
tar xfz 3.0.0.tar.gz
cd libflowmanager-3.0.0 && ./bootstrap.sh && ./configure && make && make install

# libprotoident
wget https://github.com/wanduow/libprotoident/archive/${VERSION}-1.tar.gz
tar xfz ${VERSION}-1.tar.gz
cd libprotoident-${VERSION}-1 && ./bootstrap.sh && ./configure && make && make install
