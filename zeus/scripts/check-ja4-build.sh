#!/bin/sh

set -eu

implementation="github.com/dreadl0ck/ja4plus"

check_excluded() {
    tags="$1"
    if go list -deps -tags "$tags" ./cmd | grep -qx "$implementation"; then
        printf 'JA4+ implementation is present in official build tags: %s\n' "$tags" >&2
        exit 1
    fi
}

check_excluded ""
check_excluded "noyara"
check_excluded "nodpi"
check_excluded "nodpi,noyara"
check_excluded "hyperscan,noyara"
check_excluded "appstore,nodpi,noyara"

if ! go list -deps -tags "ja4plus,nodpi,noyara" ./cmd | grep -qx "$implementation"; then
    printf 'JA4+ opt-in build does not include the implementation package\n' >&2
    exit 1
fi

printf 'official builds exclude JA4+; opt-in build includes it\n'
