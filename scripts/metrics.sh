#!/bin/sh
# ub-mode measurements for this crate: coverage, then CRAP over that coverage.
#
# The two are one command on purpose. CRAP is coverage and complexity together, so a CRAP figure
# computed over an LCOV that predates the sources attributes lines to functions that have moved -
# and it does so silently, which is the one failure mode a quality number must not have.
#
# Everything runs inside the pinned image, so the compiler that builds the code is the compiler that
# measures it. `cargo-llvm-cov` and `cargo-crap` come from the image (`docker/toolchain` upstream);
# nothing is installed on the host and nothing is installed into the shared `CARGO_HOME`, because
# `/cargo/bin` is shared between image tags and a binary left there by another base dies with
# "version GLIBC_2.34 not found".
#
# Usage:
#   ./scripts/metrics.sh coverage   # coverage summary only
#   ./scripts/metrics.sh crap       # coverage, then CRAP per function
#   ./scripts/metrics.sh all        # the same; kept so the repositories agree on one interface
#
# Environment:
#   UB_FEATURES      cargo feature selection, default `--all-features`
#   UB_IMAGE         toolchain image, default `rust:1.99.1-bullseye`
#   UB_CARGO_VOLUME  cache volume holding the registry, default `rrl-cargo-bullseye`
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
name=$(basename "$repo")
cache="${XDG_CACHE_HOME:-$HOME/.cache}/$name"
image="${UB_IMAGE:-rust:1.99.1-bullseye}"
volume="${UB_CARGO_VOLUME:-rrl-cargo-bullseye}"
features="${UB_FEATURES:---all-features}"

mkdir -p "$cache/target" "$cache/coverage"

in_image() {
    docker run --rm -u "$(id -u):$(id -g)" \
        -v "$repo:/w" -w /w \
        -v "$volume:/cargo" \
        -v "$cache/target:/target" -v "$cache/coverage:/coverage" \
        -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target \
        -e CARGO_TERM_COLOR=never \
        "$image" sh -c "PATH=/usr/local/cargo/bin:\$PATH; set -eu; $1"
}

# `--no-cfg-coverage`: the cfg-coverage remapping needs a nightly component and the numbers it moves
# are not the ones a CRAP threshold is decided on.
#
# `--summary-only` must NOT appear on the invocation that writes the LCOV. It does not merely hide
# the per-file table: it drops the `DA:` records, leaving `LF`/`LH` totals. Line coverage still
# reads correctly from those totals, so the percentage looks right - and CRAP, which needs
# per-line data to score a function, sees no coverage at all and prints 0.0% for every function at
# once. That is the signature the methodology warns about, and it was produced here by this flag.
# The table comes from `report` over the same profraw instead, which costs no second test run.
coverage() {
    in_image "cargo llvm-cov $features --lcov --output-path /coverage/lcov.info \
        --no-cfg-coverage" || {
        echo "coverage failed: no LCOV was written, so there is nothing to measure." >&2
        echo "  'test result: FAILED' above means a test broke under instrumentation;" >&2
        echo "  a feature or compile error names itself." >&2
        exit 1
    }
    in_image "cargo llvm-cov report --summary-only" || {
        echo "the LCOV was written, but the summary could not be rendered" >&2
        exit 1
    }
}

# The three measurements ub-mode asks for, and they are not interchangeable: CRAP says what to
# split or cover, dupes say what to delete, mutants say whether the tests can tell right from
# wrong. A crate can be green on one and hopeless on another - rrl-crypto sits at 5% of functions
# over the CRAP threshold while carrying a checksum function copied twice.
dupes() {
    # No coverage, no build: AST comparison only, so this is the cheap one and the one worth
    # running often. 0.8 is cargo-dupes' default and the methodology's threshold.
    in_image 'cargo dupes report --threshold 0.8 || true'
}

mutants() {
    # Scope is the only lever that scales: a crate has thousands of mutants and a full run costs a
    # day, so files are named explicitly. `-j 1` because every worker shares one CARGO_TARGET_DIR
    # and parallel workers turn into build timeouts rather than verdicts; `--timeout` because a
    # mutant that removes a loop's exit condition hangs the run forever, and a hang looks exactly
    # like a slow file in the log. `--test-tool`/`--test-command` here is a plain `cargo test`:
    # a wrapper that mounts the repo would build the unmutated file and everything would "die".
    #
    #   ./scripts/metrics.sh mutants src/kdf.rs
    shift
    in_image "cargo mutants --jobs 1 --timeout 180 --file ${*:-.} || true"
}

case "${1:-all}" in
coverage)
    coverage
    ;;
crap)
    coverage
    # `|| true`: a function over the threshold is a finding to read, not a reason to hide the rest of
    # the report. The gate, if one is wanted, is decided on the numbers and not on this exit code.
    in_image 'cargo crap --lcov /coverage/lcov.info --threshold 10 || true'
    ;;
dupes)
    dupes
    ;;
mutants)
    mutants "$@"
    ;;
all)
    coverage
    in_image 'cargo crap --lcov /coverage/lcov.info --threshold 10 || true'
    dupes
    ;;
*)
    echo "unknown measurement: $1" >&2
    echo "one of: coverage crap dupes mutants all" >&2
    exit 2
    ;;
esac
