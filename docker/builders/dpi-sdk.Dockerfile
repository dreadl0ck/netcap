ARG SUPPLIER
FROM ${SUPPLIER} AS supplier
ARG COMPONENT
RUN set -eu; cd /; case "$COMPONENT" in \
    ndpi) set -- usr/include/ndpi usr/lib/libndpi.* usr/lib/pkgconfig/libndpi.pc ;; \
    lpi) set -- usr/local/include/libflowmanager.h usr/local/include/libpacketdump.h \
        usr/local/include/libprotoident.h usr/local/include/libtrace* usr/local/include/tcp_reorder.h \
        usr/local/include/wandio.h usr/local/lib/libflowmanager.* usr/local/lib/libpacketdump* \
        usr/local/lib/libprotoident.* usr/local/lib/libtrace.* usr/local/lib/libwandio.* ;; \
    *) exit 2 ;; esac; \
    mkdir /sdk; busybox tar cf /tmp/sdk.tar "$@" usr/share/licenses/netcap; busybox tar xf /tmp/sdk.tar -C /sdk
FROM scratch
COPY --from=supplier /sdk/ /
