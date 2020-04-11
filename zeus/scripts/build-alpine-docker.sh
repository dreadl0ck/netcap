#!/bin/bash

echo "[INFO] building docker image"
cp Dockerfile-alpine Dockerfile

# in case of cache annoyances:
# docker rm -f $(docker ps -a -q)
# docker rmi -f $(docker images -a -q)

tag="dreadl0ck/netcap:alpine-v${VERSION}"

# build image
docker build --no-cache -t "$tag" .

echo "[INFO] running docker image"

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
rm -rf dist/linux_amd64_musl

# create path in dist
mkdir -p dist/linux_amd64_musl

# copy binaries from container
docker cp $CONTAINER_ID:/usr/bin/net dist/linux_amd64_musl/net

# remove container
docker rm $CONTAINER_ID

cp LICENSE dist/linux_amd64_musl
cp README.md dist/linux_amd64_musl

cd dist

# create tar archive for linux
tar -cvf netcap_musl_${VERSION}_linux_amd64_musl.tar.gz linux_amd64_musl

# add checksum - goreleaser needs to be patched for this to work
# by default the checksums.txt file is truncated when being opened
shasum -a 256 netcap_musl_${VERSION}_linux_amd64_musl.tar.gz >> checksums.txt

# remove license and readme from binary folder
rm linux_amd64_musl/LICENSE
rm linux_amd64_musl/README.md

echo "[INFO] pushing container to docker registry"
docker push "$tag"

#echo "[INFO] removing docker image"
#docker image rm "$tag"

echo "[INFO] done"