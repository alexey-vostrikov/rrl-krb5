#!/bin/sh
# Run the live tests against a real MIT KDC, inside a container.
#
#   scripts/live.sh test --test kdc            # one test binary
#   scripts/live.sh test                       # everything, live tests included
#
# Why a container: `scripts/test-kdc.sh` needs krb5kdc, kdb5_util and kadmin.local, and the gate
# image (`scripts/image.sh`) has no KDC — by design, because it is the image every gate runs in.
# This script builds `docker/kdc-stand.Dockerfile` on top of that image once, starts the stand on
# loopback *inside* the container, and runs the cargo command with the stand's environment. Nothing
# listens on the host, no port is published, and no root is needed: the stand picks ports 18888 and
# above, and writes its realm under /tmp.
#
# The cache directories are the same ones `scripts/cargo.sh` uses, keyed by image tag, so a live run
# and a gate run share compiled objects instead of building the crate twice.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TAG=kdc-stand
CACHE="${KRB5_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/rrl-krb5}"
BASE_IMAGE="${KRB5_IMAGE:-rust:1.99.1-bullseye}"
STAND_IMAGE="rrl-krb5-stand:${TAG}"

mkdir -p "$CACHE/rustup" "$CACHE/cargo-$TAG" "$ROOT/target"

# The gate image has to exist before this can be built on top of it; `scripts/cargo.sh` builds it
# on demand, so ask it for a version, which is the cheapest way to get that.
if ! docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then
  echo "building the gate image first ($BASE_IMAGE)" >&2
  "$ROOT/scripts/cargo.sh" --version >/dev/null
fi

if ! docker image inspect "$STAND_IMAGE" >/dev/null 2>&1 \
   || [ "${KRB5_REBUILD_STAND:-0}" = 1 ]; then
  echo "building $STAND_IMAGE" >&2
  docker build \
    --build-arg "BASE=$BASE_IMAGE" \
    -f "$ROOT/docker/kdc-stand.Dockerfile" \
    -t "$STAND_IMAGE" \
    "$ROOT" >&2
fi

# The stand is started here rather than by the test binary, because two test binaries and a
# `cargo test` run all need the same KDC, and starting one per run would fight over the port.
#
# `/etc/passwd` and `/etc/group` are mounted read-only because the container runs as the host's uid,
# which has no entry inside it: `kadmin.local` derives its own principal from the invoking user and
# fails with "unable to figure out a principal name" without one. Mounting the host's files gives it
# the entry, and does not give it anything it did not already have.
exec docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v /etc/passwd:/etc/passwd:ro \
  -v /etc/group:/etc/group:ro \
  -v "$ROOT:/w" \
  -v "$CACHE/cargo-$TAG:/cargo" \
  -v "$CACHE/rustup:/rustup" \
  -e CARGO_HOME=/cargo \
  -e CARGO_TARGET_DIR="/w/target/$TAG" \
  -e RUSTUP_HOME=/rustup \
  -e CARGO_TERM_COLOR=always \
  -e "KRB5_TEST_PASSWORD=${KRB5_TEST_PASSWORD:-alicepw}" \
  -w /w \
  "$STAND_IMAGE" \
  sh -c '
    set -e
    PATH=/usr/local/cargo/bin:/usr/sbin:$PATH
    export PATH
    # The stand writes /tmp/kdc-stand; it must not be the KRB5_CONFIG from the image, which points
    # at a file that does not exist until the stand has run.
    unset KRB5_CONFIG
    bash scripts/test-kdc.sh /tmp/kdc-stand >/dev/null
    set -a
    . /tmp/kdc-stand/test.env
    set +a
    export KRB5_CONFIG=/tmp/kdc-stand/krb5.conf
    exec cargo "$@"
  ' sh "$@"
