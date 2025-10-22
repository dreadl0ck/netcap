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

# Prepare Docker build context with local dependencies
echo "[INFO] preparing Docker build context with local dependencies"
rm -rf .docker-build-context
mkdir -p .docker-build-context

# Copy local dependencies
cp -r ../gopacket .docker-build-context/
cp -r ../go-dpi .docker-build-context/
cp -r ../ja3 .docker-build-context/
cp -r ../tlsx .docker-build-context/

# Copy netcap source, excluding build artifacts and the build context itself
rsync -av --exclude='.docker-build-context' --exclude='dist' --exclude='docs' --exclude='test-params' --exclude='.git' --exclude='tests' --exclude='dist-linux' --exclude='bin' --exclude='pcaps' --exclude='data' --exclude='*.log' --exclude='*.pcap' --exclude='*.pcapng' . .docker-build-context/netcap/

# Create a custom Dockerfile that references the build context structure
cp Dockerfile .docker-build-context/Dockerfile
cd .docker-build-context

# flush cache manually:
# docker rm -f $(docker ps -a -q)
# docker rmi -f $(docker images -a -q)

tag="dreadl0ck/netcap:alpine-${VERSION}"

echo "[INFO] $tag args: ${ARGS}"

# build image from the build context
# dont quote ARGS or passing arguments wont work anymore
if [ -n "${ARGS:-}" ]; then
  docker build ${ARGS} -t "$tag" .
else
  docker build -t "$tag" .
fi
BUILD_EXIT_CODE=$?

# Return to netcap directory
cd ..

# Cleanup build context
echo "[INFO] cleaning up Docker build context"
rm -rf .docker-build-context

if (( $BUILD_EXIT_CODE != 0 )); then
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