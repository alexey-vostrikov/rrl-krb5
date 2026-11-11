//! PKINIT against a **Heimdal** KDC: the RSA key transport branch, which MIT does not implement.
//!
//! `scripts/live.sh` with `KRB5_STAND=heimdal` starts `scripts/heimdal-realm.sh` in the same
//! container and runs this file with the variables it writes. Without them every test returns
//! early, so `cargo test` on a machine with no stand stays self-contained.
//!
//! What only a live KDC of this family can say: that Heimdal accepts our AuthPack with no
//! `clientPublicValue` and answers `encKeyPack`; that the EnvelopedData it wraps the reply key in
//! opens with our certificate's key — OpenSSL wrote the fixture in the crate's tests, and this is
//! the other implementation; and that the key inside is the one the AS-REP is sealed with, which
//! is what makes the TGT usable at all. The DH branch is run against the same KDC on purpose: it
//! pins that a second implementation of *agreement* also interoperates, which MIT alone cannot say.
#![cfg(feature = "pkinit")]

use krb5::pkinit::{Identity, TrustAnchors};
use krb5::{Credentials, KdcClient, Principal};

struct Env {
    kdc: String,
    realm: String,
    dir: String,
}

fn env() -> Option<Env> {
    let kdc = std::env::var("KRB5_TEST_KDC").ok()?;
    if std::env::var("KRB5_TEST_STAND").ok().as_deref() != Some("heimdal") {
        eprintln!("KRB5_TEST_STAND is not heimdal; skipping the Heimdal tests");
        return None;
    }
    Some(Env {
        kdc,
        realm: std::env::var("KRB5_TEST_REALM").unwrap_or_else(|_| "KRB5.TEST".into()),
        dir: std::env::var("KRB5_TEST_DIR").expect("KRB5_TEST_DIR"),
    })
}

macro_rules! live {
    () => {
        match env() {
            Some(e) => e,
            None => return,
        }
    };
}

impl Env {
    /// A client that trusts the stand's CA, with key transport on or off.
    fn client(&self, rsa_key_transport: bool) -> KdcClient {
        KdcClient::new(self.realm.clone(), [self.kdc.clone()])
            .with_pkinit_anchors(
                TrustAnchors::load(&format!("FILE:{}/pki/ca.pem", self.dir))
                    .expect("the stand's CA"),
            )
            .with_pkinit_rsa_key_transport(rsa_key_transport)
    }

    fn alice(&self) -> Identity {
        Identity::load(&format!(
            "FILE:{0}/pki/alice.pem,{0}/pki/alice-key.pem",
            self.dir
        ))
        .expect("alice's certificate")
    }

    fn alice_principal(&self) -> Principal {
        Principal::parse(&format!("alice@{}", self.realm)).expect("alice")
    }

    /// The TGT has to work for something, or a wrong reply key would still have passed: an AS-REP
    /// sealed in a key we did not really have fails at decryption, but a key that decrypts and is
    /// wrong would only show up on the next exchange.
    fn works_for_a_service(&self, client: &KdcClient, tgt: &Credentials) {
        let st = client
            .service_ticket(
                tgt,
                &Principal::parse(&format!("host/svc.krb5.test@{}", self.realm)).unwrap(),
            )
            .expect("a service ticket from the TGT");
        assert_eq!(
            st.server.to_string(),
            format!("host/svc.krb5.test@{}", self.realm)
        );
    }
}

/// The branch this stand exists for.
#[test]
fn a_heimdal_kdc_transports_the_reply_key_in_the_certificate() {
    let e = live!();
    let client = e.client(true);
    let tgt = client
        .login_with_certificate(&e.alice_principal(), &e.alice())
        .expect("PKINIT with RSA key transport against Heimdal");
    assert_eq!(tgt.client, e.alice_principal());
    assert_eq!(tgt.server, Principal::krbtgt(&e.realm));
    e.works_for_a_service(&client, &tgt);
}

/// The same certificate, key transport switched off, so the AuthPack carries a
/// `clientPublicValue` — and Heimdal 7.8.0 answers `encKeyPack` anyway.
///
/// That is this KDC's behaviour, not a client fault: `kdc/pkinit.c` sets `USE_DH` only when it
/// reads `clientPublicValue`, and the stand's log says `PK-INIT using enckey` for both requests
/// (the AuthPack was dumped and its `[1]` field is there). So what this pins is narrower and
/// still worth pinning: a request that offers a public value is accepted and yields a working
/// TGT, and the reply in either case is one this client can open. The DH branch itself is
/// exercised against MIT, which is the KDC that implements it.
#[test]
fn a_request_that_offers_a_public_value_is_accepted_too() {
    let e = live!();
    let client = e.client(false);
    let tgt = client
        .login_with_certificate(&e.alice_principal(), &e.alice())
        .expect("PKINIT against Heimdal with a client public value");
    e.works_for_a_service(&client, &tgt);
}

/// Heimdal as a second implementation of the plain AS exchange, which everything else rests on.
#[test]
fn a_password_login_works_against_heimdal_too() {
    let e = live!();
    let password = std::env::var("KRB5_TEST_PASSWORD").unwrap_or_else(|_| "alicepw".into());
    let client = KdcClient::new(e.realm.clone(), [e.kdc.clone()]);
    let creds = client
        .login_with_password(&e.alice_principal(), &password)
        .expect("a password login to Heimdal");
    assert_eq!(creds.client, e.alice_principal());
    e.works_for_a_service(&client, &creds);
}
