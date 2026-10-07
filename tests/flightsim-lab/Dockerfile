FROM rust:1.95.0-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump iproute2 python3 python3-paramiko openssl && rm -rf /var/lib/apt/lists/*
COPY flightsim /usr/local/bin/flightsim
COPY server.py run.sh /lab/
ENTRYPOINT ["bash", "/lab/run.sh"]
