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

docker cp $CONTAINER_ID:/netcap/GetApplicationCategories dist/linux_amd64_libc/GetApplicationCategories
docker cp $CONTAINER_ID:/netcap/GetApplications dist/linux_amd64_libc/GetApplications
docker cp $CONTAINER_ID:/netcap/GetApplicationsForCategory dist/linux_amd64_libc/GetApplicationsForCategory
docker cp $CONTAINER_ID:/netcap/GetCookieValues dist/linux_amd64_libc/GetCookieValues
docker cp $CONTAINER_ID:/netcap/GetCookiesForHTTPHost dist/linux_amd64_libc/GetCookiesForHTTPHost
docker cp $CONTAINER_ID:/netcap/GetDHCP dist/linux_amd64_libc/GetDHCP
docker cp $CONTAINER_ID:/netcap/GetDNSQuestions dist/linux_amd64_libc/GetDNSQuestions
docker cp $CONTAINER_ID:/netcap/GetDeviceContacts dist/linux_amd64_libc/GetDeviceContacts
docker cp $CONTAINER_ID:/netcap/GetDeviceIPs dist/linux_amd64_libc/GetDeviceIPs
docker cp $CONTAINER_ID:/netcap/GetDeviceProfiles dist/linux_amd64_libc/GetDeviceProfiles
docker cp $CONTAINER_ID:/netcap/GetDevices dist/linux_amd64_libc/GetDevices
docker cp $CONTAINER_ID:/netcap/GetDstPorts dist/linux_amd64_libc/GetDstPorts
docker cp $CONTAINER_ID:/netcap/GetFileTypes dist/linux_amd64_libc/GetFileTypes
docker cp $CONTAINER_ID:/netcap/GetFiles dist/linux_amd64_libc/GetFiles
docker cp $CONTAINER_ID:/netcap/GetFilesForContentType dist/linux_amd64_libc/GetFilesForContentType
docker cp $CONTAINER_ID:/netcap/GetGeolocation dist/linux_amd64_libc/GetGeolocation
docker cp $CONTAINER_ID:/netcap/GetHTTPContentTypes dist/linux_amd64_libc/GetHTTPContentTypes
docker cp $CONTAINER_ID:/netcap/GetHTTPCookies dist/linux_amd64_libc/GetHTTPCookies
docker cp $CONTAINER_ID:/netcap/GetHTTPHosts dist/linux_amd64_libc/GetHTTPHosts
docker cp $CONTAINER_ID:/netcap/GetHTTPParameters dist/linux_amd64_libc/GetHTTPParameters
docker cp $CONTAINER_ID:/netcap/GetHTTPServerNames dist/linux_amd64_libc/GetHTTPServerNames
docker cp $CONTAINER_ID:/netcap/GetHTTPStatusCodes dist/linux_amd64_libc/GetHTTPStatusCodes
docker cp $CONTAINER_ID:/netcap/GetHTTPURLs dist/linux_amd64_libc/GetHTTPURLs
docker cp $CONTAINER_ID:/netcap/GetHTTPUserAgents dist/linux_amd64_libc/GetHTTPUserAgents
docker cp $CONTAINER_ID:/netcap/GetMailAuthTokens dist/linux_amd64_libc/GetMailAuthTokens
docker cp $CONTAINER_ID:/netcap/GetMailFrom dist/linux_amd64_libc/GetMailFrom
docker cp $CONTAINER_ID:/netcap/GetMailTo dist/linux_amd64_libc/GetMailTo
docker cp $CONTAINER_ID:/netcap/GetMailUserPassword dist/linux_amd64_libc/GetMailUserPassword
docker cp $CONTAINER_ID:/netcap/GetMailUsers dist/linux_amd64_libc/GetMailUsers
docker cp $CONTAINER_ID:/netcap/GetMails dist/linux_amd64_libc/GetMails
docker cp $CONTAINER_ID:/netcap/GetParameterValues dist/linux_amd64_libc/GetParameterValues
docker cp $CONTAINER_ID:/netcap/GetParametersForHTTPHost dist/linux_amd64_libc/GetParametersForHTTPHost
docker cp $CONTAINER_ID:/netcap/GetSNIs dist/linux_amd64_libc/GetSNIs
docker cp $CONTAINER_ID:/netcap/GetSrcPorts dist/linux_amd64_libc/GetSrcPorts
docker cp $CONTAINER_ID:/netcap/GetURLsForHTTPHost dist/linux_amd64_libc/GetURLsForHTTPHost

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
