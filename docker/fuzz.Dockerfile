# The image the fuzz targets build in: the shipped toolchain, plus what libFuzzer needs.
#
# `cargo fuzz` cannot run on a stable compiler — it passes `-Zsanitizer` and
# `-Zsanitizer-coverage` — so this image carries a second toolchain beside the pinned stable one.
# The nightly is *newer* than the stable, which is the point: `rrl-crypto` and `rrl-krb-common`
# declare `rust-version = "1.99.1"`, and a nightly older than that refuses to build them at all
# (`error: rustc 1.98.0-nightly is not supported by the following packages`). A nightly from before
# 1.99.1 branched is therefore not a usable fuzz compiler for this crate, however recently it was
# published.
#
# `clang` because `libfuzzer-sys` compiles libFuzzer's own C++ sources through the `cc` crate, and
# the bullseye base ships no compiler. bullseye's clang 11 is enough: the sanitizer instrumentation
# comes from rustc's own LLVM, and only the runtime archive is built here.
#
# Built on top of the toolchain image rather than beside it, so that the rustc the fuzz corpus is
# measured against is the rustc the crate ships with — and so that this file inherits the archive
# sources and the glibc the rest of the repository asserts.
ARG BASE=rust:1.99.1-bullseye
FROM ${BASE}

# A nightly dated after 1.99.1's branch point: `nightly-2026-11-05` is rustc 1.101.0-nightly.
# Pinned for the same reason every other tool here is: a fuzz run that fails because the compiler
# moved is a red build nobody can reproduce.
ARG NIGHTLY=2026-11-05
# Pinned as in the workflow's own `cargo install`: a change of fuzzer is a deliberate upgrade.
ARG CARGO_FUZZ=0.13.2

RUN apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends clang \
 && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install "nightly-${NIGHTLY}" --profile minimal \
 && rustc "+nightly-${NIGHTLY}" --version

RUN cargo install cargo-fuzz --locked --version "${CARGO_FUZZ}" \
 && cargo fuzz --version

# The nightly must be able to build what the stable toolchain builds: asserting the version is what
# turns "the pin is old" from a message in the middle of a build into a failure here.
RUN set -eu; \
    night="$(rustc "+nightly-${NIGHTLY}" --version | cut -d' ' -f2)"; \
    stable="$(rustc --version | cut -d' ' -f2)"; \
    echo "nightly=$night stable=$stable"; \
    test "$(printf '%s\n%s\n' "$stable" "$night" | sort -V | tail -1)" = "$night"

RUN clang --version && cargo fuzz --version && python3 --version
