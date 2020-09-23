FROM ubuntu:18.04 as builder
RUN apt-get clean
RUN apt-get update
RUN apt-get install -y software-properties-common
RUN add-apt-repository ppa:longsleep/golang-backports
RUN apt-get update
RUN apt-get install -y golang-go

RUN apt-get install -y apt-transport-https curl lsb-release wget autogen autoconf libtool gcc libpcap-dev linux-headers-generic git vim
RUN echo "deb https://dl.bintray.com/wand/general $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
RUN echo "deb https://dl.bintray.com/wand/libtrace $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
RUN echo "deb https://dl.bintray.com/wand/libflowmanager $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
RUN echo "deb https://dl.bintray.com/wand/libprotoident $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/wand.list
RUN curl --silent "https://bintray.com/user/downloadSubjectPublicKey?username=wand" | apt-key add -
RUN apt-get update

RUN wget https://github.com/ntop/nDPI/archive/3.2.tar.gz
RUN tar xfz 3.2.tar.gz
RUN cd nDPI-3.2 && ./autogen.sh && ./configure && make && make install

RUN apt install -y liblinear-dev libprotoident libprotoident-dev libprotoident-tools libtrace4-dev libtrace4-tools
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV VERSION XXX
ARG tags
ENV TAGS $tags
RUN echo "tags: $TAGS"

ENV CFLAGS -I/usr/local/include/
ENV LDFLAGS -ltrace -lndpi -lpcap -lm -pthread

RUN env
RUN find / -iname ndpi_main.h
RUN find / -iname libprotoident.h
RUN find / -iname libtrace.h

RUN go build -mod=readonly ${TAGS} -ldflags "-s -w -X github.com/dreadl0ck/netcap.Version=v${VERSION}" -o /netcap/bin/net -i github.com/dreadl0ck/netcap/cmd

FROM ubuntu:18.04
ARG IPV6_SUPPORT=true
RUN apt-get update
RUN apt install -y libpcap-dev software-properties-common ca-certificates liblzo2-2 libkeyutils-dev
RUN update-ca-certificates
WORKDIR /netcap
COPY --from=builder /netcap/bin/* /usr/bin/
COPY --from=builder /usr/lib/* /usr/lib/
COPY --from=builder /usr/local/lib/* /usr/lib/
#RUN ls -la
CMD ["/bin/sh"]

