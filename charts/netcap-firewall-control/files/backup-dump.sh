#!/bin/sh
set -eu
umask 077
ulimit -c 0
: "${PGSERVICEFILE:?mounted pg_service.conf required}"
: "${PGSERVICE:?service name required}"
: "${DATABASE_NAMESPACE:?dedicated schema required}"
: "${MAX_DUMP_BYTES:?dump file limit required}"
case "$PGSERVICE" in ''|*[!A-Za-z0-9_]*) exit 64 ;; esac
case "$DATABASE_NAMESPACE" in ''|[!a-z]*|*[!a-z0-9_]*|public|information_schema|pg_*) exit 64 ;; esac
test "${#DATABASE_NAMESPACE}" -le 48
case "$MAX_DUMP_BYTES" in ''|*[!0-9]*) exit 64 ;; esac
test "$MAX_DUMP_BYTES" -ge 512
test "$MAX_DUMP_BYTES" -le 1073741824
test "$((MAX_DUMP_BYTES % 512))" -eq 0
test ! -e /work/control.dump
trap 'rm -f /work/control.dump.part' EXIT
# The pinned Debian image's /bin/sh uses 512-byte RLIMIT_FSIZE blocks.
ulimit -f "$((MAX_DUMP_BYTES / 512))"
if ! pg_dump --no-password --dbname="service=$PGSERVICE sslmode=verify-full" \
  --schema="$DATABASE_NAMESPACE" --strict-names --format=custom --no-owner --no-acl \
  --lock-wait-timeout=5s --file=/work/control.dump.part 2>/work/dump-error.log; then
  printf '%s\n' 'Postgres snapshot failed; no upload attempted' >&2
  exit 1
fi
if ! pg_restore --list /work/control.dump.part >/dev/null 2>/work/dump-error.log; then
  printf '%s\n' 'Postgres archive validation failed; no upload attempted' >&2
  exit 1
fi
mv /work/control.dump.part /work/control.dump
rm -f /work/dump-error.log
printf '%s\n' 'Consistent schema archive ready'
