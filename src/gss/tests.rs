//! What the mechanism layer promises, checked through it and against the direct API.
//!
//! The tests are built the way a caller uses the layer — a registry, a context, tokens — and two of
//! them cross the boundary deliberately: a token the layer built must be accepted by the Kerberos API
//! directly, and one that API built must be accepted through the layer. A layer that agreed only with
//! itself would pass every other test here and break at the first real peer.

use super::*;
use crate::client::Principal;
use crate::initiator::tests::{keytab_with, mint};
use crate::initiator::{GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG};
use crate::key::Key;

fn setup() -> (Credentials, Keytab) {
    let service = Principal::parse("HTTP/web.example.com@EXAMPLE.COM").unwrap();
    let client = Principal::parse("alice@EXAMPLE.COM").unwrap();
    let service_key = Key::new(18, vec![7; 32]).unwrap();
    let session_key = Key::random(18).unwrap();
    (
        mint(&service_key, &session_key, &client, &service),
        keytab_with(&service, &service_key),
    )
}

fn registry() -> Registry {
    Registry::with_krb5()
}

/// The OID constants are the content octets of the very OIDs the framing code splices into tokens.
///
/// Pinned because the two spellings live in different modules: `KRB5_MECH_OID` is DER with its tag
/// and length, `KRB5` here is content only, and a length octet that drifted would make every token
/// from this layer unreadable to its own acceptor — which the round-trip tests would catch, but only
/// with a message about a truncated token rather than about the OID.
#[test]
fn the_mechanism_oids_are_the_content_octets_of_the_framed_ones() {
    assert_eq!(
        crate::der::tlv(crate::der::OBJECT_IDENTIFIER, KRB5),
        crate::initiator::KRB5_MECH_OID.to_vec()
    );
    assert_eq!(
        crate::der::tlv(crate::der::OBJECT_IDENTIFIER, MS_KRB5),
        crate::acceptor::MS_KRB5_OID.to_vec()
    );
    assert_eq!(dotted_oid(KRB5).as_deref(), Some("1.2.840.113554.1.2.2"));
    assert_eq!(dotted_oid(MS_KRB5).as_deref(), Some("1.2.840.48018.1.2.2"));
}

/// `gss_indicate_mechs` lists the mechanism once, with its alias, in preference order.
#[test]
fn the_indicated_mechanisms_are_in_preference_order() {
    let registry = registry();
    assert_eq!(registry.len(), 1, "one mechanism, two OIDs");
    assert_eq!(registry.indicate_mechs(), vec![KRB5, MS_KRB5]);
    assert_eq!(
        registry.first().map(Mechanism::name),
        Some("krb5"),
        "the first is what a caller that names no mechanism gets"
    );
}

/// A full mutual handshake through the layer: two tokens, both sides established, names known.
#[test]
fn a_handshake_through_the_layer_establishes_and_names_both_sides() {
    let (creds, keytab) = setup();
    let registry = registry();

    let (mut ini, token) = registry
        .initiator(
            None,
            &creds,
            GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG,
        )
        .expect("an initiator context");
    let token = token.expect("Kerberos emits an AP-REQ");
    assert!(
        !ini.is_established(),
        "nothing is established before the reply"
    );
    assert_eq!(ini.mechanism(), "krb5");
    assert_eq!(ini.mech_oid(), KRB5);

    let (acc, reply) = registry.acceptor(&keytab, &token).expect("accepted");
    assert!(
        acc.is_established(),
        "the acceptor is established by the AP-REQ"
    );
    assert_eq!(acc.client(), Some("alice@EXAMPLE.COM"));
    assert_eq!(
        acc.service(),
        Some("HTTP/web.example.com@EXAMPLE.COM"),
        "the service the ticket was for"
    );
    assert_ne!(
        acc.flags() & GSS_C_MUTUAL_FLAG,
        0,
        "mutual was asked for and granted"
    );

    let reply = reply.expect("mutual authentication answers with an AP-REP");
    assert_eq!(ini.step(&reply).expect("the AP-REP is consumed"), None);
    assert!(ini.is_established());
    assert_ne!(ini.flags() & GSS_C_MUTUAL_FLAG, 0);
}

/// A layer-built token is accepted by the Kerberos API directly, and the reverse.
///
/// The layer adds no framing of its own — the `[APPLICATION 0]` wrapper is already the mechanism's —
/// and this is the test that says so without reading the code: each side's octets go straight into
/// the other side's entry point.
#[test]
fn the_layer_and_the_direct_api_speak_the_same_octets() {
    let (creds, keytab) = setup();

    // Layer initiator → direct acceptor.
    let (_, token) = registry()
        .initiator(None, &creds, GSS_C_MUTUAL_FLAG)
        .expect("a context");
    let token = token.expect("a token");
    let (ctx, _) = KerberosContext::accept_token(&keytab, &token)
        .expect("the direct API accepts what the layer built");
    assert_eq!(ctx.client_principal, "alice@EXAMPLE.COM");

    // Direct initiator → layer acceptor.
    let (_, direct) = InitiatorContext::new(&creds, GSS_C_MUTUAL_FLAG).expect("a context");
    let (ctx, _) = registry()
        .acceptor(&keytab, &direct)
        .expect("the layer accepts what the direct API built");
    assert!(ctx.is_established());
    assert_eq!(ctx.client(), Some("alice@EXAMPLE.COM"));
}

/// Per-message tokens work in both directions, and the send counter advances per token.
#[test]
fn per_message_tokens_travel_both_ways_and_the_counter_advances() {
    let (creds, keytab) = setup();
    let registry = registry();
    let (mut ini, token) = registry
        .initiator(
            None,
            &creds,
            GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG,
        )
        .expect("a context");
    let (acc, reply) = registry
        .acceptor(&keytab, &token.expect("a token"))
        .expect("accepted");
    ini.step(&reply.expect("an AP-REP")).expect("consumed");

    let ti = ini.per_message().expect("keys after establishment");
    let ta = acc.per_message().expect("keys after acceptance");
    // Not zero: RFC 4121 §4.1.1 lets the initiator pick its starting sequence number, so the
    // assertion is that the counter advances from wherever the context began.
    let start = ti.next_send_seq();

    let wrapped = ti.wrap(b"ping").expect("wrapped");
    let got = ta.unwrap(&wrapped).expect("verified and decrypted");
    assert_eq!(got.message, b"ping");
    assert_eq!(
        got.seq, start,
        "the token carries the number it was built with"
    );
    assert_eq!(ti.next_send_seq(), start + 1, "the counter advanced once");

    let wrapped = ta.wrap(b"pong").expect("wrapped");
    let got = ti.unwrap(&wrapped).expect("verified and decrypted");
    assert_eq!(got.message, b"pong");

    // A MIC over a message that stays in the clear.
    let mic = ti.mic(b"a signed message").expect("a MIC");
    assert!(
        ta.verify_mic(&mic, b"a signed message").is_ok(),
        "the MIC verifies over the same bytes"
    );
    assert!(
        ta.verify_mic(&mic, b"another message").is_err(),
        "and not over different ones"
    );
}

/// The Microsoft OID is the same mechanism: a token framed with it is accepted.
///
/// Windows lists `1.2.840.48018.1.2.2` first in its mechanism list, and an acceptor that only knew
/// the standard OID would refuse every Windows client while this crate's Kerberos API would take the
/// same ticket.
#[test]
fn the_microsoft_oid_is_the_same_mechanism() {
    let (creds, keytab) = setup();
    let (_, token) = registry()
        .initiator(None, &creds, GSS_C_MUTUAL_FLAG)
        .expect("a context");
    let token = token.expect("a token");

    // Replace the OID's content: nine octets for nine, so every length stays valid.
    let at = token
        .windows(KRB5.len())
        .position(|w| w == KRB5)
        .expect("the token names the standard OID");
    let mut ms = token.clone();
    ms[at..at + MS_KRB5.len()].copy_from_slice(MS_KRB5);

    let (ctx, _) = registry()
        .acceptor(&keytab, &ms)
        .expect("the alias names the same mechanism");
    assert_eq!(ctx.mechanism(), "krb5");
    assert_eq!(ctx.client(), Some("alice@EXAMPLE.COM"));
    assert_eq!(registry().find(MS_KRB5).map(Mechanism::name), Some("krb5"));
}

/// A mechanism this build does not have is refused by name, dotted, with what we do have.
#[test]
fn an_unknown_mechanism_is_refused_and_named() {
    // NTLMSSP, 1.3.6.1.4.1.311.2.2.10.
    const NTLM: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A];
    let token = crate::der::tlv(
        0x60,
        &[
            crate::der::tlv(crate::der::OBJECT_IDENTIFIER, NTLM),
            b"whatever".to_vec(),
        ]
        .concat(),
    );
    let (_, keytab) = setup();
    let err = registry()
        .acceptor(&keytab, &token)
        .expect_err("no NTLM here")
        .to_string();
    assert!(
        err.contains("1.3.6.1.4.1.311.2.2.10") && err.contains("krb5"),
        "the message must name the OID and what we have: {err}"
    );

    // The same for an initiator that asks for it explicitly. The API takes the OID's content
    // octets, so the request is the ten bytes without the tag and length DER would add.
    let (creds, _) = setup();
    let err = registry()
        .initiator(Some(NTLM), &creds, 0)
        .expect_err("no NTLM here")
        .to_string();
    assert!(err.contains("1.3.6.1.4.1.311.2.2.10"), "{err}");
}

/// A token that is not a GSS initial context token is refused rather than guessed at.
#[test]
fn a_token_without_the_application_tag_is_refused() {
    let (_, keytab) = setup();
    for token in [
        &b""[..],
        b"not a token",
        &[0x61, 0x00][..],             // a different application tag
        &[0x60, 0x02, 0x02, 0x01][..], // an INTEGER instead of an OID
    ] {
        let err = registry()
            .acceptor(&keytab, token)
            .expect_err("not an initial context token")
            .to_string();
        assert!(
            err.contains("initial context token"),
            "the message must say what it is not: {err}"
        );
    }
}

/// An empty registry answers nothing and says why.
///
/// The default is an empty registry rather than Kerberos-by-default: a build that registered a
/// mechanism implicitly would answer a request it was never told to answer.
#[test]
fn an_empty_registry_refuses_with_a_reason() {
    let (creds, _) = setup();
    let err = Registry::new()
        .initiator(None, &creds, 0)
        .expect_err("nothing registered")
        .to_string();
    assert!(err.contains("register one"), "{err}");
    assert!(Registry::new().is_empty());
}

/// Selection follows the peer's order, not ours — RFC 4178 §4.2.1.
#[test]
fn selection_follows_the_peers_preference() {
    const NTLM: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A];
    let registry = registry();
    assert_eq!(
        registry.select(&[NTLM, KRB5]).map(Mechanism::name),
        Some("krb5"),
        "NTLM is unknown, Kerberos is the first we support"
    );
    assert_eq!(
        registry.select(&[NTLM]).map(Mechanism::name),
        None,
        "a peer offering only what we lack leaves nothing to pick"
    );
    assert_eq!(
        registry.select(&[MS_KRB5, KRB5]).map(Mechanism::name),
        Some("krb5"),
        "the alias picks the same mechanism"
    );
}

/// The acceptor refuses a second token rather than reporting success for an exchange it did not
/// understand.
#[test]
fn the_acceptor_has_nothing_to_consume() {
    let (creds, keytab) = setup();
    let registry = registry();
    let (_, token) = registry.initiator(None, &creds, 0).expect("a context");
    let (mut acc, _) = registry
        .acceptor(&keytab, &token.expect("a token"))
        .expect("accepted");
    let err = acc
        .step(b"another token")
        .expect_err("Kerberos completes in one round")
        .to_string();
    assert!(err.contains("one round"), "{err}");
}

/// Per-message keys before the handshake finishes are an error, not a context that fails later.
#[test]
fn per_message_before_establishment_is_refused() {
    let (creds, _) = setup();
    let (ini, _) = registry()
        .initiator(None, &creds, GSS_C_MUTUAL_FLAG)
        .expect("a context");
    let err = ini
        .per_message()
        .expect_err("no keys until the AP-REP arrives")
        .to_string();
    assert!(err.contains("not established"), "{err}");
}

/// The per-message object is built once: two calls hand out the same counter.
///
/// A fresh object per call would restart SND_SEQ at the context's initial number, and two callers
/// would emit tokens bearing the same sequence number — accepted by the peer's MAC check, rejected by
/// its replay window, long after the bug.
#[test]
fn per_message_is_built_once_and_keeps_one_counter() {
    let (creds, keytab) = setup();
    let registry = registry();
    let (mut ini, token) = registry
        .initiator(None, &creds, GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG)
        .expect("a context");
    let (acc, reply) = registry
        .acceptor(&keytab, &token.expect("a token"))
        .expect("accepted");
    ini.step(&reply.expect("an AP-REP")).expect("consumed");

    let first = ini.per_message().expect("keys");
    let start = first.next_send_seq();
    let wrapped = first.wrap(b"one").expect("wrapped");
    let second = ini.per_message().expect("keys again");
    assert_eq!(
        second.next_send_seq(),
        start + 1,
        "the second handle is the same object, not a reset counter"
    );
    assert_eq!(
        acc.per_message()
            .expect("keys")
            .unwrap(&wrapped)
            .expect("verified")
            .message,
        b"one"
    );
}

/// A server's registry: Kerberos first, SPNEGO second, and the OID list says so.
///
/// The order is the decision [`Registry::all`] documents. SPNEGO is a wrapper, so a caller that
/// names no mechanism must not get one — it would pay a round trip for a negotiation nobody asked
/// for.
#[test]
fn everything_this_build_has_lists_krb5_first_then_spnego() {
    let registry = Registry::all();
    assert_eq!(registry.len(), 2);
    assert_eq!(
        registry
            .mechanisms()
            .map(Mechanism::name)
            .collect::<Vec<_>>(),
        vec!["krb5", "spnego"]
    );
    assert_eq!(registry.indicate_mechs(), vec![KRB5, MS_KRB5, SPNEGO]);
    assert_eq!(dotted_oid(SPNEGO).as_deref(), Some("1.3.6.1.5.5.2"));
    assert_eq!(
        registry.first().map(Mechanism::name),
        Some("krb5"),
        "a caller that names no mechanism gets Kerberos, not a wrapper"
    );
}

/// One registry serves both kinds of client: the token's own OID decides, not a parameter.
///
/// That is the property an HTTP `Negotiate` endpoint needs — the same port answers a client that
/// wraps Kerberos in SPNEGO and one that sends a bare Kerberos token.
#[test]
fn one_registry_serves_both_mechanisms() {
    let (creds, keytab) = setup();
    let registry = Registry::all();

    // A bare Kerberos token: its OID is the mechanism's own, so it goes to `Krb5`.
    let (_, bare) = registry
        .initiator(Some(KRB5), &creds, GSS_C_MUTUAL_FLAG)
        .expect("a kerberos context");
    let (ctx, _) = registry
        .acceptor(&keytab, &bare.expect("an AP-REQ"))
        .expect("accepted");
    assert_eq!(ctx.mechanism(), "krb5");

    // A SPNEGO token: it goes to `Spnego`, and the context it yields is the negotiation's.
    let (_, wrapped) = registry
        .initiator(Some(SPNEGO), &creds, GSS_C_MUTUAL_FLAG)
        .expect("a spnego context");
    let (ctx, reply) = registry
        .acceptor(&keytab, &wrapped.expect("a NegTokenInit"))
        .expect("accepted");
    assert_eq!(ctx.mechanism(), "spnego");
    assert!(ctx.is_established(), "the optimistic token completed it");
    assert_eq!(ctx.mech_oid(), SPNEGO);
    assert_eq!(ctx.client(), Some("alice@EXAMPLE.COM"));
    assert!(
        reply.is_some(),
        "the first answer always names the mechanism"
    );
}

/// A full SPNEGO negotiation through the layer, both sides established and naming the client.
#[test]
fn a_spnego_negotiation_through_the_layer_establishes() {
    let (creds, keytab) = setup();
    let registry = Registry::all();

    let (mut ini, token) = registry
        .initiator(Some(SPNEGO), &creds, GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG)
        .expect("a context");
    assert!(!ini.is_established());

    let (acc, reply) = registry
        .acceptor(&keytab, &token.expect("a token"))
        .expect("accepted");
    assert!(acc.is_established());
    assert_eq!(acc.client(), Some("alice@EXAMPLE.COM"));

    // The initiator consumes the NegTokenResp and is established too.
    let reply = reply.expect("a NegTokenResp");
    assert!(ini.step(&reply).expect("consumed").is_none());
    assert!(ini.is_established());
    assert_ne!(ini.flags() & GSS_C_MUTUAL_FLAG, 0);
}

/// Per-message tokens work through a SPNEGO context, in both directions.
///
/// The number they start from is the **SPNEGO state's** `send_seq`, not the inner Kerberos
/// context's: the `mechListMIC` exchange spends sequence numbers, so a context that resumed at the
/// Kerberos numbers would reuse them. The two coincide in this exchange — our initiator offers
/// Kerberos first, so no MIC is spent — and the case where they differ needs a peer that lists
/// Kerberos second, which is built and pinned in `spnego::tests` (where `recv_seq`/`send_seq` are
/// asserted around the MIC). What this test pins is the wiring: that the layer asks the SPNEGO state
/// for the number at all, and that the tokens it produces are the ones the peer expects.
#[test]
fn per_message_through_a_negotiated_context_travels_both_ways() {
    let (creds, keytab) = setup();
    let registry = Registry::all();
    let (mut ini, token) = registry
        .initiator(
            Some(SPNEGO),
            &creds,
            GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG,
        )
        .expect("a context");
    let (acc, reply) = registry
        .acceptor(&keytab, &token.expect("a token"))
        .expect("accepted");
    ini.step(&reply.expect("a NegTokenResp")).expect("consumed");

    let ti = ini.per_message().expect("keys after establishment");
    let ta = acc.per_message().expect("keys after acceptance");
    let asked = ti.next_send_seq();
    let wrapped = ti.wrap(b"ping").expect("wrapped");
    let got = ta.unwrap(&wrapped).expect("verified and decrypted");
    assert_eq!(got.message, b"ping");
    assert_eq!(
        got.seq, asked,
        "the token carries the number the context's counter was at"
    );

    let wrapped = ta.wrap(b"pong").expect("wrapped");
    let got = ti.unwrap(&wrapped).expect("verified and decrypted");
    assert_eq!(got.message, b"pong");

    // A MIC over a message that stays readable, through the same negotiated context.
    let mic = ti.mic(b"signed").expect("a MIC");
    assert!(ta.verify_mic(&mic, b"signed").is_ok());
    assert!(ta.verify_mic(&mic, b"other").is_err());
}
