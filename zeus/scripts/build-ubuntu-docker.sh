#!/bin/bash

cp Dockerfile-ubuntu Dockerfile


tag="dreadl0ck/netcap:ubuntu-v${VERSION}"

echo "[INFO] building docker image $tag"

# in case of cache annoyances:
# docker rm -f $(docker ps -a -q)
# docker rmi -f $(docker images -a -q)

# build image
docker build -t "$tag" .

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

ARCHIVE="netcap_${VERSION}_linux_amd64_libc"

echo "[INFO] preparing dist folder, CONTAINER_ID: $CONTAINER_ID, archive: $ARCHIVE"

# clean up
rm -rf dist/${ARCHIVE}

# create path in dist
mkdir -p dist/${ARCHIVE}

# copy binaries from container
docker cp $CONTAINER_ID:/usr/bin/net dist/${ARCHIVE}/net

# remove container
docker rm $CONTAINER_ID

cp LICENSE dist/${ARCHIVE}
cp README.md dist/${ARCHIVE}

cd dist

# create tar archive for linux
tar -cvf ${ARCHIVE}.tar.gz ${ARCHIVE}

# add checksum - goreleaser needs to be patched for this to work
# by default the checksums.txt file is truncated when being opened
shasum -a 256 ${ARCHIVE}.tar.gz >> checksums.txt

# remove license and readme from binary folder
rm ${ARCHIVE}/LICENSE
rm ${ARCHIVE}/README.md

# TODO: make pushing configurable
exit 0

echo "[INFO] pushing container to docker registry"
docker push "$tag"

#echo "[INFO] removing docker image"
#docker image rm "$tag"

echo "[INFO] done"
