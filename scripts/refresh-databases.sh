#!/bin/sh
set -eu
umask 077
: "${NC_DBS_PUBLISH_ROOT:?}"
: "${NC_DBS_POLICY:?}"
: "${NC_DBS_POLICY_SHA256:?}"
: "${NC_DBS_SIGNING_KEY:?}"
: "${NC_DBS_SIGNING_CERT:?}"
publisher=${NETCAP_DBS_PUBLISHER:-/usr/local/bin/netcap-dbs-server}
status_writer=${NETCAP_DBS_STATUS_WRITER:-/root/netcap-db-publisher/db-refresh-status.py}
count_reader=${NETCAP_DBS_COUNT_READER:-/root/netcap-db-publisher/db-previous-count.py}
mkdir -p "$NC_DBS_PUBLISH_ROOT"
mkdir -p "$NC_DBS_PUBLISH_ROOT/v3"
chmod 755 "$NC_DBS_PUBLISH_ROOT" "$NC_DBS_PUBLISH_ROOT/v3"
exec 9>"$NC_DBS_PUBLISH_ROOT/refresh.lock"
flock -n 9 || exit 0
base=$(mktemp -d "$NC_DBS_PUBLISH_ROOT/build-XXXXXXXX")
stage=previous-publication
status() { python3 "$status_writer" "$NC_DBS_PUBLISH_ROOT/v3" "$1" "$stage"; }
trap 'status failed; printf "%s\n" "Database refresh failed; retained acquisition at $base" >&2' 0
trap 'exit 1' HUP INT TERM
status running
previous=$(python3 "$count_reader" "$NC_DBS_PUBLISH_ROOT")
stage=acquisition; status running
"$publisher" -mode candidate -root "$base" >"$base/acquisition.log" 2>&1
candidate=$(python3 -c 'import pathlib,sys; matches=list(pathlib.Path(sys.argv[1]).glob("candidate-*/dbs/SOURCE_CANDIDATE.json")); assert len(matches)==1; print(matches[0].parent)' "$base")
registry="$base/approvals.json"
stage=policy; status running
"$publisher" -mode approve -root "$candidate" -policy "$NC_DBS_POLICY" -policy-sha256 "$NC_DBS_POLICY_SHA256" -approvals "$registry" -previous-count "$previous"
pin=$(sha256sum "$registry")
stage=pack; status running
"$publisher" -mode pack -root "$candidate" -output "$NC_DBS_PUBLISH_ROOT/v3" -approvals "$registry" -approvals-sha256 "${pin%% *}"
stage=sign; status running
"$publisher" -mode sign -output "$NC_DBS_PUBLISH_ROOT/v3" -approvals "$registry" -policy "$NC_DBS_POLICY" -key "$NC_DBS_SIGNING_KEY" -certificate "$NC_DBS_SIGNING_CERT" -sequence "$(date +%s)"
stage=publication-recovery; status running
python3 "$count_reader" "$NC_DBS_PUBLISH_ROOT" >/dev/null
# The signer verifies the complete archive before atomically committing signed-latest.
trap - 0
stage=complete; status success
printf '%s\n' "Published signed release at $(date -u +%FT%TZ)"
