FROM --platform=linux/amd64 dreadl0ck/netcap-builder:ubuntu-latest as builder

# Copy netcap source
WORKDIR /netcap
COPY . .

ENV VERSION XXX
ARG TAGS
RUN echo "tags: $TAGS"

RUN echo go build ${TAGS} -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd
# CGO is still required for libpcap support even without DPI
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build ${TAGS} -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/bin/net github.com/dreadl0ck/netcap/cmd

#RUN ls -la /usr/lib/

FROM --platform=linux/amd64 ubuntu:18.04
ARG IPV6_SUPPORT=true
RUN apt-get update
RUN apt install -y --fix-missing libpcap0.8 software-properties-common ca-certificates liblzo2-2 libkeyutils-dev
RUN update-ca-certificates
WORKDIR /netcap
COPY --from=builder /netcap/bin/* /usr/bin/
#COPY --from=builder /usr/lib/* /usr/lib/
COPY --from=builder /usr/local/lib/* /usr/lib/
CMD ["/bin/sh"]
