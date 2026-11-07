#!/bin/sh
set -eu
root=$(git rev-parse --show-toplevel)
image=prom/prometheus:v3.8.0@sha256:d936808bdea528155c0154a922cd42fd75716b8bb7ba302641350f9f3eaeba09
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,src=$root/configs,dst=/fixtures,readonly" --workdir /fixtures \
  --entrypoint /bin/promtool "$image" check rules firewall-operations-rules.yaml
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,src=$root/configs,dst=/fixtures,readonly" --workdir /fixtures \
  --entrypoint /bin/promtool "$image" test rules firewall-operations-rules-test.yaml
