#!/bin/bash

cp Dockerfile-ubuntu Dockerfile


tag="dreadl0ck/netcap:ubuntu-v${VERSION}"

echo "[INFO] building docker image $tag"

# in case of cache annoyances:
# docker rm -f $(docker ps -a -q)
# docker rmi -f $(docker images -a -q)

# build image
docker build --no-cache -t "$tag" .

echo "[INFO] running docker image $tag"

docker run "$tag"

# docker image ls

# grab container ID
echo "[INFO] looking for $tag container ID"
CONTAINER_ID=$(docker ps -a -f ancestor=$tag -q --latest)
if [[ $CONTAINER_ID == "" ]]; then
	echo "[ERROR] no docker container found"
	exit 1
fi

echo "[INFO] preparing dist folder, CONTAINER_ID: $CONTAINER_ID"

# clean up
rm -rf dist/linux_amd64_libc

# create path in dist
mkdir -p dist/linux_amd64_libc

# copy binaries from container
docker cp $CONTAINER_ID:/netcap/net.capture dist/linux_amd64_libc/net.capture
docker cp $CONTAINER_ID:/netcap/net.label dist/linux_amd64_libc/net.label
docker cp $CONTAINER_ID:/netcap/net.collect dist/linux_amd64_libc/net.collect
docker cp $CONTAINER_ID:/netcap/net.agent dist/linux_amd64_libc/net.agent
docker cp $CONTAINER_ID:/netcap/net.proxy dist/linux_amd64_libc/net.proxy
docker cp $CONTAINER_ID:/netcap/net.export dist/linux_amd64_libc/net.export
docker cp $CONTAINER_ID:/netcap/net.dump dist/linux_amd64_libc/net.dump
docker cp $CONTAINER_ID:/netcap/net.util dist/linux_amd64_libc/net.util
docker cp $CONTAINER_ID:/netcap/net.transform dist/linux_amd64/net.transform

# remove container
docker rm $CONTAINER_ID

cp LICENSE dist/linux_amd64_libc
cp README.md dist/linux_amd64_libc

cd dist

# create tar archive for linux
tar -cvf netcap_libc_${VERSION}_linux_amd64.tar.gz linux_amd64_libc

# add checksum - goreleaser needs to be patched for this to work
# by default the checksums.txt file is truncated when being opened
shasum -a 256 netcap_libc_${VERSION}_linux_amd64.tar.gz >> checksums.txt

# remove license and readme from binary folder
rm linux_amd64_libc/LICENSE
rm linux_amd64_libc/README.md

echo "[INFO] pushing container to docker registry"
docker push "$tag"

#echo "[INFO] removing docker image"
#docker image rm "$tag"

echo "[INFO] done"
