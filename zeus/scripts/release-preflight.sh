#!/bin/sh
# Checks everything zeus release needs before it creates the tag. Every check
# here failed once after a tag was already public.
set -u
fail=0
check() {
    if eval "$2" >/dev/null 2>&1; then
        echo "[ok]   $1"
    else
        echo "[FAIL] $1"
        [ -n "${3:-}" ] && echo "       $3"
        fail=1
    fi
}

: "${VERSION:?VERSION must be set (zeus/commands.yml globals)}"
tag="v$VERSION"

check "working tree is clean" 'test -z "$(git status --porcelain)"' "commit or stash first; version-bump commits only version files"
check "on master" 'test "$(git rev-parse --abbrev-ref HEAD)" = master'
check "master matches origin" 'git fetch -q origin master && test "$(git rev-parse HEAD)" = "$(git rev-parse origin/master)"' "git pull --rebase && git push"
check "tag $tag does not exist yet" '! git rev-parse -q --verify "refs/tags/$tag" && ! git ls-remote --exit-code --tags origin "$tag"' "bump VERSION in zeus/commands.yml"
check "RELEASE_NOTES.md starts with $tag" 'head -1 RELEASE_NOTES.md | grep -q "^## $tag "'
check "release notes validate" 'python3 scripts/check-release-notes.py'
check "gh is authenticated" 'gh auth status'
check "goreleaser config validates" 'goreleaser check .goreleaser.yml'
check "YARA_X_PREFIX names a YARA-X install" 'test -n "${YARA_X_PREFIX:-}" && YARA_X_PREFIX="$YARA_X_PREFIX" sh scripts/with-yara-x.sh true' 'export YARA_X_PREFIX="$PWD/.native/yara-x" (build it with scripts/build-yara-x.sh)'
check "docker daemon runs" 'docker info'
check "docker can pull through its proxy" 'docker pull -q alpine:3.24.4@sha256:93b41ef40b1677fce8fcc64ff4af09daddfacf5040afde618bc46c1e2d1cc7d4' "Docker Desktop's manual proxy (127.0.0.1:1030) must be running"
check "pnpm can list frontend licenses" '(cd cmd/capture/webui/frontend && pnpm install --frozen-lockfile && pnpm licenses list --prod --json)' "pnpm install --frozen-lockfile --force in cmd/capture/webui/frontend"
check "ssh can push to GitHub" 'ssh -o BatchMode=yes -T git@github.com 2>&1 | grep -q "successfully authenticated"' "ssh-add --apple-load-keychain"

if make try-webui TRY_BINARY=; then
    echo "[ok]   Try WebUI browser regression gate"
else
    echo "[FAIL] Try WebUI browser regression gate (requires Chrome or CHROME_PATH)"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "release preflight failed; nothing was tagged"
    exit 1
fi
echo "release preflight passed for $tag"
