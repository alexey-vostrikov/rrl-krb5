# A toolchain image that also carries MIT krb5, for the live tests.
#
# The gate image (`rust:1.99.1-bullseye`, built by `scripts/image.sh` and shared with the sibling
# repositories) has the compiler and nothing else: it is what the gates run in, and adding a KDC to
# it would make every gate run install one. This image is the other job — `scripts/test-kdc.sh`
# needs `krb5kdc`, `kdb5_util` and `kadmin.local`, and the tests need them on loopback, so they have
# to be in the same container as the compiler that builds them.
#
# Debian bullseye's krb5 is 1.18, which is old enough to be careful about: it has no SPAKE and no
# ECDH PKINIT, so `KRB5_TEST_OTP`, `KRB5_TEST_PKINIT_ECDH` and the SPAKE cases are off here and are
# exercised on a host with a newer MIT. Everything the forwarded-credential, AS/TGS, referral,
# kpasswd and kadmin tests need is in 1.18.
ARG BASE=rust:1.99.1-bullseye
FROM ${BASE}

ENV DEBIAN_FRONTEND=noninteractive
# No `krb5-pkinit` on purpose. `scripts/test-kdc.sh` turns PKINIT on when openssl and MIT's pkinit
# plugin are both present, and bullseye's openssl is 1.1.1, which has no `ca -gencrl
# -crl_lastupdate` (that arrived in 3.0) — the stand's CRL fixture then fails and takes the whole
# stand with it. PKINIT's live cases are run on a host with openssl 3; this image is for the
# exchanges MIT 1.18 supports fully: AS, TGS, referrals, forwarded credentials, kpasswd, kadmin.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      krb5-kdc \
      krb5-admin-server \
      krb5-user \
      libkrb5-dev \
      openssl \
      python3 \
      python3-gssapi \
      procps \
 && rm -rf /var/lib/apt/lists/*

# The stand writes its realm, database and keytabs under /tmp/kdc-stand, unprivileged, exactly as it
# would on a host; nothing here listens on a privileged port.
ENV KRB5_CONFIG=/tmp/kdc-stand/krb5.conf
WORKDIR /w

# Heimdal, built from its release tarball, for the one branch MIT has never implemented: PKINIT RSA
# key transport (`encKeyPack`, RFC 4556 §3.2.3.2). One stand, two KDCs behind `KRB5_STAND`: adding
# a second image would mean a second set of caches and a second thing to keep in step.
#
# 7.8.0 on purpose. It is the last release that takes the RSA branch without a switch
# (`kdc/pkinit.c`: `else cp->keyex = USE_RSA;`); master 7.99.1 gates it behind
# `[kdc] pkinit_allow_rsa_key_transport`, and a released tarball needs no autoreconf. The checksum
# is pinned because the build fetches the source at image-build time and nothing else verifies it.
ARG HEIMDAL_VERSION=7.8.0
ARG HEIMDAL_SHA256=fd87a207846fa650fd377219adc4b8a8193e55904d8a752c2c3715b4155d8d38
RUN apt-get update \
 && apt-get install -y --no-install-recommends libtool bison flex texinfo ca-certificates curl \
 && curl -fsSL -o /tmp/heimdal.tar.gz \
      "https://github.com/heimdal/heimdal/releases/download/heimdal-${HEIMDAL_VERSION}/heimdal-${HEIMDAL_VERSION}.tar.gz" \
 && echo "${HEIMDAL_SHA256}  /tmp/heimdal.tar.gz" | sha256sum -c - \
 && tar xzf /tmp/heimdal.tar.gz -C /tmp \
 && cd "/tmp/heimdal-${HEIMDAL_VERSION}" \
 && ./configure --prefix=/opt/heimdal --sysconfdir=/opt/heimdal/etc --localstatedir=/var >/tmp/heimdal-configure.log 2>&1 \
 && make -j"$(nproc)" >/tmp/heimdal-make.log 2>&1 \
 && make install >/tmp/heimdal-install.log 2>&1 \
 && rm -rf "/tmp/heimdal-${HEIMDAL_VERSION}" /tmp/heimdal.tar.gz /tmp/heimdal-*.log \
 && /opt/heimdal/sbin/kdc --version | head -1
