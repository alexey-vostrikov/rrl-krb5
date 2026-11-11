#!/bin/sh
# Run a libFuzzer target in the image that carries the nightly compiler, `clang` and `cargo-fuzz`.
#
# Usage:
#   scripts/fuzz.sh build -O acceptor_token
#   scripts/fuzz.sh run -O acceptor_token -- -max_total_time=30
#   fuzz/seed.py && scripts/fuzz.sh run -O          # every target, seeded from testdata/
#
# Why an image rather than the host's compiler: `cargo fuzz` needs a nightly (`-Zsanitizer`), and
# the nightly has to be newer than the crate's own `rust-version` — see `docker/fuzz.Dockerfile`.
# Building the fuzz image on top of the shipped toolchain image keeps one rustc for the crate and
# for its instrumentation, which is what makes a crash found here a crash in the code that ships.
#
# Two details carried over from `scripts/cargo.sh`, for the same reasons:
#
# * `-u $(id -u):$(id -g)` — a container that writes `fuzz/target/` as root leaves a tree the host
#   cannot clean up, and the corpus it grows is root's too.
# * `CARGO_HOME` in a writable mount — the image's own home is root-owned. The registry cache is
#   shared with `cargo.sh`'s by tag: the crates are the same crates.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CACHE="${KRB5_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/rrl-krb5}"
. "$ROOT/scripts/image.sh"

FUZZ_IMAGE="${KRB5_FUZZ_IMAGE:-rrl-krb5-fuzz:$TAG}"
CARGO_HOME_SRC="${KRB5_CARGO_VOLUME:-$CACHE/cargo-fuzz-$TAG}"

mkdir -p "$CARGO_HOME_SRC" "$ROOT/fuzz"
# The fuzz image is built *on* the toolchain image, so that one has to exist first — the same
# on-demand build `cargo.sh` does, and the same message when it cannot be made.
ensure_image

if ! docker image inspect "$FUZZ_IMAGE" >/dev/null 2>&1; then
    echo "building $FUZZ_IMAGE from docker/fuzz.Dockerfile (first run only)" >&2
    docker build -t "$FUZZ_IMAGE" -f "$ROOT/docker/fuzz.Dockerfile" \
        --build-arg "BASE=$IMAGE" "$ROOT" >&2 || {
        echo "could not build $FUZZ_IMAGE; fuzzing cannot run without it" >&2
        exit 1
    }
fi

# The nightly is named explicitly: the image's default toolchain is the stable one, and a
# `rustup default` inside the image would be a second place to keep a pin in step.
NIGHTLY="${KRB5_NIGHTLY:-nightly-2026-11-05}"

exec docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$ROOT:/w" \
  -v "$CARGO_HOME_SRC:/cargo" \
  -e CARGO_HOME=/cargo \
  -e CARGO_TARGET_DIR=/w/fuzz/target \
  -e RUSTUP_TOOLCHAIN="$NIGHTLY" \
  -e ASAN_OPTIONS=detect_odr_violation=0 \
  -w /w/fuzz \
  "$FUZZ_IMAGE" \
  sh -c 'exec cargo fuzz "$@"' sh "$@"
