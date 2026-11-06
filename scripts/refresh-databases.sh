#!/bin/sh
set -eu
umask 077
: "${NC_DBS_PUBLISH_ROOT:?}"
: "${NC_DBS_POLICY:?}"
: "${NC_DBS_POLICY_SHA256:?}"
: "${NC_DBS_SIGNING_KEY:?}"
: "${NC_DBS_SIGNING_CERT:?}"
publisher=${NETCAP_DBS_PUBLISHER:-/usr/local/bin/netcap-dbs-server}
mkdir -p "$NC_DBS_PUBLISH_ROOT"
mkdir -p "$NC_DBS_PUBLISH_ROOT/v3"
chmod 755 "$NC_DBS_PUBLISH_ROOT" "$NC_DBS_PUBLISH_ROOT/v3"
exec 9>"$NC_DBS_PUBLISH_ROOT/refresh.lock"
flock -n 9 || exit 0
base=$(mktemp -d "$NC_DBS_PUBLISH_ROOT/build-XXXXXXXX")
trap 'printf "%s\n" "Database refresh failed; retained acquisition at $base" >&2' 0
"$publisher" -mode candidate -root "$base" >"$base/acquisition.log" 2>&1
candidate=$(python3 -c 'import pathlib,sys; matches=list(pathlib.Path(sys.argv[1]).glob("candidate-*/dbs/SOURCE_CANDIDATE.json")); assert len(matches)==1; print(matches[0].parent)' "$base")
registry="$base/approvals.json"
previous=$(python3 -c 'import json,pathlib,sys; p=pathlib.Path(sys.argv[1]); print(json.loads(p.read_text())["count"] if p.exists() else 400000)' "$NC_DBS_PUBLISH_ROOT/last-count.json")
"$publisher" -mode approve -root "$candidate" -policy "$NC_DBS_POLICY" -policy-sha256 "$NC_DBS_POLICY_SHA256" -approvals "$registry" -previous-count "$previous"
pin=$(sha256sum "$registry")
"$publisher" -mode pack -root "$candidate" -output "$NC_DBS_PUBLISH_ROOT/v3" -approvals "$registry" -approvals-sha256 "${pin%% *}"
"$publisher" -mode sign -output "$NC_DBS_PUBLISH_ROOT/v3" -approvals "$registry" -policy "$NC_DBS_POLICY" -key "$NC_DBS_SIGNING_KEY" -certificate "$NC_DBS_SIGNING_CERT" -sequence "$(date +%s)"
python3 -c 'import json,pathlib,sqlite3,sys; c=sqlite3.connect("file:"+sys.argv[1]+"/netcap.sqlite?mode=ro",uri=True); n=c.execute("select count(*) from nvd").fetchone()[0]; p=pathlib.Path(sys.argv[2]); tmp=p.with_suffix(".tmp"); tmp.write_text(json.dumps({"count":n})); tmp.replace(p)' "$candidate" "$NC_DBS_PUBLISH_ROOT/last-count.json"
# The signer verifies the complete archive before atomically committing signed-latest.
trap - 0
printf '%s\n' "Published signed release at $(date -u +%FT%TZ)"
