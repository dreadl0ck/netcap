#!/bin/bash
# Alternate build script for linux binaries in docker container using goreleaser and not the build-linux command.
# Not used atm.

if [ -z "$NODPI" ]; then
  NODPI=true
fi

if $NODPI; then
  echo "[INFO] copying the docker/ubuntu-nodpi/Dockerfile into the project root"
  cp docker/ubuntu-nodpi/Dockerfile Dockerfile
else
  echo "[INFO] copying the docker/ubuntu/Dockerfile into the project root"
  cp docker/ubuntu/Dockerfile Dockerfile
fi

# generate version, add update the VERSION env var in the Dockerfile that was moved to the project root
zeus gen-version

# in case of cache annoyances:
# docker rm -f $(docker ps -a -q)
# docker rmi -f $(docker images -a -q)

tag="dreadl0ck/netcap:ubuntu-${VERSION}"

echo "[INFO] $tag args: ${ARGS}"

# build image directly from project root
# dont quote ARGS or passing arguments wont work anymore
if [ -n "${ARGS:-}" ]; then
  docker build ${ARGS} -t "$tag" -f Dockerfile .
else
  docker build -t "$tag" -f Dockerfile .
fi
BUILD_EXIT_CODE=$?

if (( $BUILD_EXIT_CODE != 0 )); then
	echo "[ERROR] building container failed"
	exit 1
fi

# Create container without running it (avoids architecture issues on non-Linux hosts)
echo "[INFO] creating container from image $tag"
CONTAINER_ID=$(docker create "$tag")
if [[ $CONTAINER_ID == "" ]]; then
	echo "[ERROR] failed to create docker container"
	exit 1
fi
echo "[INFO] container ID: $CONTAINER_ID"

ARCHIVE="netcap-${VERSION}-linux-amd64-libc"

echo "[INFO] preparing dist-linux folder, CONTAINER_ID: $CONTAINER_ID, archive: $ARCHIVE"

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
mkdir -p dist-linux/${ARCHIVE}/docs
cp "docs/NETCAP Software Report.pdf" dist-linux/${ARCHIVE}/docs/

cd dist-linux

# create tar archive for linux
tar -czvf ${ARCHIVE}.tar.gz ${ARCHIVE}

# add checksum - goreleaser needs to be patched for this to work
# by default the checksums.txt file is truncated when being opened
shasum -a 256 ${ARCHIVE}.tar.gz >> checksums.txt

# remove license, readme and docs from binary folder
rm ${ARCHIVE}/LICENSE
rm ${ARCHIVE}/README.md
rm -rf ${ARCHIVE}/docs

echo "[INFO] pushing container to docker registry"
docker push "$tag"

#echo "[INFO] removing docker image"
#docker image rm "$tag"

echo "[INFO] done"
