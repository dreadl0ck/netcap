#!/bin/bash

if [ -z "$NODPI" ]; then
  NODPI=true
fi

echo "[INFO] building docker image"

if $NODPI; then
  echo "[INFO] copying the docker/alpine-nodpi/Dockerfile into the project root"
  cp docker/alpine-nodpi/Dockerfile Dockerfile
else
  echo "[INFO] copying the docker/alpine/Dockerfile into the project root"
  cp docker/alpine/Dockerfile Dockerfile
fi

# generate version, add update the VERSION env var in the Dockerfile that was moved to the project root
zeus gen-version

# flush cache manually:
# docker rm -f $(docker ps -a -q)
# docker rmi -f $(docker images -a -q)

tag="dreadl0ck/netcap:alpine-${VERSION}"

echo "[INFO] $tag args: ${ARGS}"

# build image
# dont quote ARGS or passing arguments wont work anymore
docker build ${ARGS} -t "$tag" .
if (( $? != 0 )); then
	echo "[ERROR] building container failed"
	exit 1
fi

echo "[INFO] running docker image"

docker run "$tag"

# echo "[INFO] docker images"
# docker image ls

# grab container ID
echo "[INFO] looking for $tag container ID"
CONTAINER_ID=$(docker ps -a -f ancestor=$tag -q --latest)
if [[ $CONTAINER_ID == "" ]]; then
	echo "[ERROR] no docker container found"
	exit 1
fi

ARCHIVE="netcap_${VERSION}_linux_amd64_musl"

echo "[INFO] preparing dist-linux folder, CONTAINER_ID: $CONTAINER_ID"

# clean up
rm -rf dist-linux/${ARCHIVE}

# create path in dist
mkdir -p dist-linux/${ARCHIVE}

# copy binaries from container
docker cp $CONTAINER_ID:/usr/bin/net dist-linux/${ARCHIVE}/net

# remove container
docker rm $CONTAINER_ID

cp LICENSE dist-linux/${ARCHIVE}
cp README.md dist-linux/${ARCHIVE}

cd dist-linux

# create tar archive for linux
tar -czvf ${ARCHIVE}.tar.gz ${ARCHIVE}

# add checksum
# goreleaser will truncate the checksums.txt file upon opening
shasum -a 256 ${ARCHIVE}.tar.gz >> checksums.txt

# remove license and readme from binary folder
rm ${ARCHIVE}/LICENSE
rm ${ARCHIVE}/README.md

echo "[INFO] pushing container to docker registry"
docker push "$tag"

#echo "[INFO] removing docker image"
#docker image rm "$tag"

echo "[INFO] done"