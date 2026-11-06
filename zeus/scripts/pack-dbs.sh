#!/bin/bash
set -euo pipefail

DBS_DIR=""
OUTPUT_DIR="./release-v3"
APPROVALS="${NC_DBS_APPROVALS:-}"
APPROVALS_SHA256="${NC_DBS_APPROVALS_SHA256:-}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dbs-dir) DBS_DIR="${2:?missing candidate directory}"; shift 2 ;;
        -o|--output-dir) OUTPUT_DIR="${2:?missing output directory}"; shift 2 ;;
        -a|--approvals) APPROVALS="${2:?missing reviewed-record file}"; shift 2 ;;
        --approvals-sha256) APPROVALS_SHA256="${2:?missing operator registry SHA-256}"; shift 2 ;;
        -D|--deploy)
            [[ "${2:-}" == false ]] || { printf '%s\n' 'Deployment is not supported by the packer.' >&2; exit 2; }
            shift 2 ;;
        -h|--help)
            printf '%s\n' 'Usage: pack-dbs.sh -d CANDIDATE -o OUTPUT -a REVIEWED_RECORDS --approvals-sha256 TRUSTED_PIN' \
                'Uses NETCAP_BIN (default: net) and the shared v3 verifier. No deployment or cleanup.'
            exit 0 ;;
        *) printf 'Unsupported option: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[[ -n "$DBS_DIR" && -n "$APPROVALS" && "$APPROVALS_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
    printf '%s\n' 'An explicit candidate directory, external reviewed-record file and trusted SHA-256 pin are required.' >&2
    exit 2
}
exec "${NETCAP_BIN:-net}" util --pack-dbs "$DBS_DIR" --dbs-output "$OUTPUT_DIR" --dbs-approvals "$APPROVALS" --dbs-approvals-sha256 "$APPROVALS_SHA256"
