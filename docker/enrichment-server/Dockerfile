FROM alpine:3.24.4@sha256:93b41ef40b1677fce8fcc64ff4af09daddfacf5040afde618bc46c1e2d1cc7d4
COPY netcap-enrichment-server /netcap-enrichment-server
USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["/netcap-enrichment-server"]
CMD ["-mode", "serve", "-root", "/data/enrichment", "-addr", ":8080"]
