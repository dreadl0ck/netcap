#!/bin/sh
set -eu
umask 077
ulimit -c 0
: "${RESTIC_REPOSITORY:?operator-initialized repository required}"
: "${RESTIC_PASSWORD_FILE:?mounted repository password required}"
: "${BACKUP_HOST:?stable backup host required}"
: "${BACKUP_TAG:?unique scope tag required}"
: "${KEEP_DAILY:?retention required}"
: "${KEEP_WEEKLY:?retention required}"
: "${KEEP_MONTHLY:?retention required}"
: "${PRUNE:?explicit prune setting required}"
case "$BACKUP_HOST" in netcap-*) ;; *) exit 64 ;; esac
case "$BACKUP_TAG" in netcap-control/*/*/*/*) ;; *) exit 64 ;; esac
case "$BACKUP_HOST$BACKUP_TAG" in *[!A-Za-z0-9_./-]*) exit 64 ;; esac
for value in "$KEEP_DAILY" "$KEEP_WEEKLY" "$KEEP_MONTHLY"; do
  case "$value" in ''|*[!0-9]*) exit 64 ;; esac
  test "$value" -le 366
done
test "$KEEP_DAILY" -ge 1
case "$PRUNE" in true|false) ;; *) exit 64 ;; esac
test -s /work/control.dump
trap 'rm -f /work/control.dump' EXIT
set --
if [ -f /repository/ca.crt ]; then set -- --cacert /repository/ca.crt; fi
# Do not initialize a repository or forget snapshots before a successful backup.
if ! restic "$@" backup --quiet --host "$BACKUP_HOST" --tag "$BACKUP_TAG" \
  /work/control.dump >/cache/backup.log 2>&1; then
  printf '%s\n' 'Encrypted backup failed; retention was not applied' >&2
  exit 1
fi
if [ "$PRUNE" = true ]; then set -- "$@" --prune; fi
if ! restic forget --quiet --host "$BACKUP_HOST" --tag "$BACKUP_TAG" \
  --group-by host,tags,paths --keep-daily "$KEEP_DAILY" --keep-weekly "$KEEP_WEEKLY" \
  --keep-monthly "$KEEP_MONTHLY" "$@" >/cache/retention.log 2>&1; then
  printf '%s\n' 'Encrypted backup succeeded but scoped retention failed' >&2
  exit 1
fi
printf '%s\n' 'Encrypted backup and scoped retention completed'
