#!/bin/bash

# build image
docker build -t "netcap-linux" .

docker run netcap-linux

# docker image ls

# grab container ID
echo "[INFO] looking for linux container ID"
CONTAINER_ID=$(docker ps -a -f ancestor=netcap-linux -q)
if [[ $CONTAINER_ID == "" ]]; then
	echo "[ERROR] no docker container found"
	exit 1
fi

# create path in dist
mkdir -p ../dist/linux_amd64

# extract binary from container
docker cp $CONTAINER_ID:/go/nc-linux ../dist/linux_amd64/netcap

# remove container
docker rm $CONTAINER_ID