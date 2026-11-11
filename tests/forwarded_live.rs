//! The forwarded-credential path against a **live MIT KDC**.
//!
//! `scripts/live.sh` starts an MIT KDC inside a container and runs this file with the variables it
//! writes; without `KRB5_TEST_KDC` every test returns early, so `cargo test` on a machine with no
//! KDC stays self-contained.
//!
//! What only a live KDC can say: that MIT accepts a `TGS-REQ` carrying the FORWARDED option from
//! our encoder, that it seals the reply in the key we expect, and that the ticket it hands back is
//! one our own decoder reads. The unit tests pin the octets; this pins the conversation.

use krb5::ccache::CacheName;
use krb5::{Credentials, KdcClient, Key, Principal};

struct Env {
    client: KdcClient,
    realm: String,
}

fn env() -> Option<Env> {
    let kdc = std::env::var("KRB5_TEST_KDC").ok()?;
    let realm = std::env::var("KRB5_TEST_REALM").unwrap_or_else(|_| "KRB5.TEST".into());
    Some(Env {
        // A forwarded ticket is made from the TGT, so the TGT has to be forwardable: MIT refuses
        // otherwise with KDC_ERR_BADOPTION and the text "TGT NOT FORWARDABLE", which is the
        // refusal this stand produced the first time it ran.
        client: KdcClient::new(realm.clone(), [kdc]).with_forwardable(true),
        realm,
    })
}

macro_rules! live {
    () => {
        match env() {
            Some(e) => e,
            None => {
                eprintln!("KRB5_TEST_KDC not set; skipping the live forwarded-credentials test");
                return;
            }
        }
    };
}

/// A cache of this test's own, in the stand's directory.
fn cache(name: &str) -> CacheName {
    let dir = std::env::var("KRB5_TEST_DIR").expect("KRB5_TEST_DIR");
    CacheName::File(std::path::PathBuf::from(dir).join(name))
}

fn login(e: &Env, cache: &CacheName) -> Credentials {
    let password = std::env::var("KRB5_TEST_PASSWORD").unwrap_or_else(|_| "alicepw".into());
    let client = Principal::parse(&format!("alice@{}", e.realm)).expect("alice");
    e.client
        .kinit_with_password(&client, &password, cache)
        .expect("logging in to the live KDC")
}

/// The forwarded ticket a live MIT KDC issues, opened the way the peer would open it.
#[test]
fn a_live_kdc_issues_a_forwarded_ticket_the_peer_can_open() {
    let e = live!();
    let cache = cache("forwarded.cc");
    let tgt = login(&e, &cache);

    // The key the peer and we share: in a GSS session the acceptor's subkey, here any key both
    // sides hold, which is the same statement.
    let session_key = Key::random(18).unwrap();
    let packed = e
        .client
        .forwarded_creds(&cache, "127.0.0.1", &session_key)
        .expect("MIT must issue a forwarded ticket for a forwardable TGT");

    let creds = krb5::client::decode_krb_cred(&packed, &[&session_key])
        .expect("the peer opens the KRB-CRED with the key the session agreed on");
    assert_eq!(creds.client.realm, e.realm);
    assert_eq!(
        creds.client, tgt.client,
        "the forwarded credential is for the same user"
    );
    assert!(
        creds.flags & FORWARDED != 0,
        "the forwarded ticket carries the forwarded flag, got {:#010x}",
        creds.flags
    );
    assert!(
        creds.ticket.first() == Some(&0x61),
        "the ticket is an [APPLICATION 1] value"
    );
}

/// Heimdal's address rule as a live KDC shows it: MIT issues its TGTs addressless, so the forwarded
/// ticket is addressless too, and the request still succeeds. The other branch — source with
/// addresses, forwarded bound to `host` — is pinned by the unit test that builds such a cache entry;
/// `scripts/test-kdc.sh` has no switch to make MIT issue an addressed TGT.
#[test]
fn an_addressless_source_gives_an_addressless_forwarded_ticket() {
    let e = live!();
    let cache = cache("forwarded-addrs.cc");
    login(&e, &cache);

    let cc = cache.read().expect("the cache the login wrote");
    let tgt = cc.tgt(0).expect("a TGT in the cache");
    assert!(
        cc.addresses_of(&tgt.server, now()).is_empty(),
        "MIT issues addressless TGTs by default, and this case pins that"
    );

    let session_key = Key::random(18).unwrap();
    let packed = e
        .client
        .forwarded_creds(&cache, "127.0.0.1", &session_key)
        .expect("an addressless source still allows a forwarded ticket");
    krb5::client::decode_krb_cred(&packed, &[&session_key]).expect("and it opens");
}

/// Unix seconds, so the address lookup and the cache agree on what "not expired" means.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// RFC 4120 §5.4.4 bit 2, `forwarded`.
const FORWARDED: u32 = 1 << 29;
