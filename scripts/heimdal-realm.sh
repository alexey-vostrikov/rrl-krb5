#!/bin/bash
# A Heimdal realm on loopback, for the live tests that MIT cannot serve.
#
#   bash scripts/heimdal-realm.sh [dir]        # default /tmp/kdc-stand
#
# Why a second KDC at all: PKINIT RSA key transport (`encKeyPack`, RFC 4556 §3.2.3.2) is the one
# exchange MIT implements on neither side — `pkinit_clnt.c` and `pkinit_srv.c` have no such branch —
# while Heimdal's KDC takes it whenever the AuthPack carries no `clientPublicValue` (7.8.0
# unconditionally, master behind `[kdc] pkinit_allow_rsa_key_transport`). The image has Heimdal
# built from its release tarball at /opt/heimdal; this script makes a realm for it.
#
# It writes into `dir` and nothing outside it: the database, the keytabs, the certificates, the
# configuration and the log. `scripts/live.sh` runs it inside a container, so the directory goes
# away with the container; run by hand, it leaves exactly that one directory to delete.
#
# Two things Heimdal does its own way and this script therefore spells out:
#
# * the database is named under `[kdc] database`, not `[hdb]`: `dbinfo.c` reads that binding and
#   otherwise falls back to the compiled-in `HDB_DB_DIR "/heimdal"`, which is /var/heimdal/heimdal
#   and not writable by an unprivileged uid;
# * a client certificate's subject has to be mapped to a principal by hand (`pki-mapping`), because
#   Heimdal does not read `id-pkinit-san` out of a client's certificate unless
#   `pkinit_princ_in_cert` is on.
set -eu

DIR=${1:-/tmp/kdc-stand}
REALM=${KRB5_TEST_REALM:-KRB5.TEST}
PORT=${KRB5_TEST_PORT:-18888}
P="$DIR/pki"
HEIMDAL=${HEIMDAL_PREFIX:-/opt/heimdal}
export KRB5_CONFIG="$DIR/krb5.conf"
# Heimdal installs `kdc` under libexec, not sbin.
KDC="$HEIMDAL/libexec/kdc"
[ -x "$KDC" ] || KDC="$HEIMDAL/sbin/kdc"
# `/usr/bin/kadmin` in this image is MIT's; Heimdal's has to be named or PATH decides.
KADMIN="$HEIMDAL/bin/kadmin"
export PATH="$HEIMDAL/sbin:$HEIMDAL/bin:$PATH"

rm -rf "$DIR"
mkdir -p "$DIR" "$P"

# Two files, because Heimdal wants two: `kdc.conf` is the database and the KDC's own settings (it
# is what `kadmin -l` is pointed at with `-c`), `krb5.conf` is what a client — and the tests — read.
cat >"$DIR/kdc.conf" <<CONF
[libdefaults]
    default_realm = $REALM

[kdc]
    ports = $PORT
    database = {
        dbname = $DIR/heimdal
        mkey_file = $DIR/m-key
        acl_file = $DIR/kadmind.acl
        # The iprop log; without it kadmin tries /var/heimdal/log and warns on every run.
        log_file = $DIR/log
    }
    enable-pkinit = true
    pkinit_identity = FILE:$P/kdc.pem,$P/kdc-key.pem
    pkinit_anchors = FILE:$P/ca.pem
    pkinit_princ_in_cert = false
    pkinit_mappings_file = $DIR/pki-mapping

[logging]
    kdc = FILE:$DIR/kdc.log
CONF

cat >"$KRB5_CONFIG" <<CONF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    forwardable = true
    ticket_lifetime = 24h
    default_ccache_name = FILE:$DIR/ccache

[realms]
    $REALM = {
        kdc = 127.0.0.1:$PORT
    }
CONF

# The certificates. The KDC's carries `id-pkinit-KPKdc` and names krbtgt/REALM@REALM in its
# `id-pkinit-san`, which is what our client insists on — the same fixture `scripts/test-kdc.sh`
# makes for MIT, so the client-side code under test is the same in both stands.
cat >"$P/ext.cnf" <<EXT
[kdc_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name
[kdc_princ_name]
realm=EXP:0,GeneralString:$REALM
principal_name=EXP:1,SEQUENCE:kdc_principal_seq
[kdc_principal_seq]
name_type=EXP:0,INTEGER:2
name_string=EXP:1,SEQUENCE:kdc_principals
[kdc_principals]
princ1=GeneralString:krbtgt
princ2=GeneralString:$REALM
EXT

o() { openssl "$@" 2>/dev/null; }
o req -x509 -newkey rsa:2048 -nodes -keyout "$P/ca-key.pem" -out "$P/ca.pem" \
    -days 3650 -subj "/CN=Test PKINIT CA"
o req -newkey rsa:2048 -nodes -keyout "$P/kdc-key.pem" -out "$P/kdc.req" -subj "/CN=kdc"
o x509 -req -in "$P/kdc.req" -CA "$P/ca.pem" -CAkey "$P/ca-key.pem" -CAcreateserial \
    -out "$P/kdc.pem" -days 365 -extfile "$P/ext.cnf" -extensions kdc_cert
o req -newkey rsa:2048 -nodes -keyout "$P/alice-key.pem" -out "$P/alice.req" -subj "/CN=alice"
o x509 -req -in "$P/alice.req" -CA "$P/ca.pem" -CAkey "$P/ca-key.pem" -CAcreateserial \
    -out "$P/alice.pem" -days 365

# The principal the certificate stands for: Heimdal compares the subject name as hx509 formats it,
# which for a single CN is `CN=alice`.
printf 'alice@%s:CN=alice\n' "$REALM" >"$DIR/pki-mapping"

# The realm. `kadmin -l` is the local mode: it edits the database named in `kdc.conf` directly and
# needs no kadmind, no network and no credentials. Heimdal's `kadmin` is built with getarg's short
# options only (`--long` is "invalid option"), and `init` prompts for the realm's ticket lifetimes,
# so its stdin is closed rather than left on a terminal that is not there.
$KADMIN -l -c "$DIR/kdc.conf" init --realm-max-ticket-life=10h --realm-max-renewable-life=7d "$REALM" >/dev/null
$KADMIN -l -c "$DIR/kdc.conf" add --use-defaults --password=alicepw "alice@$REALM" >/dev/null
$KADMIN -l -c "$DIR/kdc.conf" add --use-defaults --random-key "host/svc.krb5.test@$REALM" >/dev/null
$KADMIN -l -c "$DIR/kdc.conf" ext_keytab --keytab="$DIR/service.keytab" "host/svc.krb5.test@$REALM" >/dev/null
chmod 600 "$DIR/service.keytab"

# The KDC itself. Heimdal writes its log through `[logging] kdc`, so a failed start is readable
# afterwards instead of silent.
"$KDC" -c "$DIR/kdc.conf" >"$DIR/kdc.out" 2>&1 &
echo $! >"$DIR/kdc.pid"

# Wait for the port to answer: Heimdal binds both UDP and TCP, and the tests use both.
for _ in $(seq 1 100); do
  if (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if ! (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
  echo "the Heimdal KDC did not start; $DIR/kdc.out and $DIR/kdc.log follow" >&2
  cat "$DIR/kdc.out" >&2 || true
  cat "$DIR/kdc.log" >&2 || true
  exit 1
fi

cat >"$DIR/test.env" <<ENV
KRB5_TEST_KDC=127.0.0.1:$PORT
KRB5_TEST_REALM=$REALM
KRB5_TEST_DIR=$DIR
KRB5_TEST_PASSWORD=alicepw
KRB5_TEST_STAND=heimdal
KRB5_TEST_PKINIT=1
ENV
echo "$DIR/test.env"
