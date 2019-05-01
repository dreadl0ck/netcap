#!/bin/bash

# make this script callable from project root dir
cd docker

echo "[INFO] building docker image"

# build image
docker build -t "netcap-linux" .

echo "[INFO] running docker image"

docker run netcap-linux

# docker image ls

# grab container ID
echo "[INFO] looking for netcap-linux container ID"
CONTAINER_ID=$(docker ps -a -f ancestor=netcap-linux -q --latest)
if [[ $CONTAINER_ID == "" ]]; then
	echo "[ERROR] no docker container found"
	exit 1
fi

echo "[INFO] preparing dist folder, CONTAINER_ID: $CONTAINER_ID"

# clean up
rm -rf ../dist/linux_amd64

# create path in dist
mkdir -p ../dist/linux_amd64

# copy binaries from container
docker cp $CONTAINER_ID:/go/net.cap ../dist/linux_amd64/net.cap
docker cp $CONTAINER_ID:/go/net.label ../dist/linux_amd64/net.label
docker cp $CONTAINER_ID:/go/net.collector ../dist/linux_amd64/net.collector
docker cp $CONTAINER_ID:/go/net.sensor ../dist/linux_amd64/net.sensor
docker cp $CONTAINER_ID:/go/net.proxy ../dist/linux_amd64/net.proxy
docker cp $CONTAINER_ID:/go/net.exporter ../dist/linux_amd64/net.exporter

# remove container
docker rm $CONTAINER_ID

cp ../LICENSE ../dist/linux_amd64
cp ../README.md ../dist/linux_amd64

cd ../dist

# create tar archive for linux
tar -cvf netcap_${VERSION}_linux_amd64.tar.gz linux_amd64

# add checksum - goreleaser needs to be patched for this to work
# by default the checksums.txt file is truncated when being opened
shasum -a 256 netcap_${VERSION}_linux_amd64.tar.gz > checksums.txt

# remove license and readme from binary folder
rm linux_amd64/LICENSE
rm linux_amd64/README.md

echo "[INFO] removing docker image"
docker image rm netcap-linux

echo "[INFO] done"
