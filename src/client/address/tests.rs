//! `HostAddress` and the forwarded-credential path: what goes on the wire, and what a peer can
//! read back out of what we send.
//!
//! The centre of gravity here is `caddr [8]`: an address that is encoded with the wrong type or in
//! host byte order is an address no KDC and no acceptor will match, and both sides would still
//! report success. So the octets are pinned literally, against the IANA numbers RFC 4120 §7.5.10
//! registers — 20 for IPv4, 24 for IPv6 — and against an address whose bytes are recognisable
//! (`192.0.2.7` is RFC 5737's documentation prefix, so a mix-up shows as a wrong literal rather
//! than a plausible one).

use crate::client::address::{
    ADDRTYPE_INET, ADDRTYPE_INET6, HostAddress, decode_caddr, encode_caddr, of_host,
};
use crate::client::{
    Credentials, KdcClient, Principal, ReqTimes, encode_encrypted_data, encode_key,
};
use crate::der;
use crate::key::Key;

/// The `forwardable` ticket flag (RFC 4120 §5.4.4, bit 1).
const FORWARDABLE: u32 = 1 << 30;
use std::net::{IpAddr, SocketAddr};

fn v4(ip: [u8; 4]) -> HostAddress {
    HostAddress::of(SocketAddr::from((ip, 0)))
}

#[test]
fn the_address_types_are_the_numbers_rfc_4120_registers() {
    // Literals, not the constants: a test that compares a constant to itself proves nothing.
    assert_eq!(ADDRTYPE_INET, 20, "IPv4 is IANA address type 20");
    assert_eq!(ADDRTYPE_INET6, 24, "IPv6 is IANA address type 24");
}

#[test]
fn an_ipv4_address_encodes_as_its_four_octets_in_order() {
    let encoded = HostAddress::of(SocketAddr::from(([192, 0, 2, 7], 0))).encode();
    // SEQUENCE { [0] INTEGER 20, [1] OCTET STRING 192.0.2.7 } — 13 octets in all.
    assert_eq!(
        encoded,
        vec![
            0x30, 0x0d, // SEQUENCE, 13 octets
            0xa0, 0x03, 0x02, 0x01, 20, // addr-type [0] = 20
            0xa1, 0x06, 0x04, 0x04, 0xc0, 0x00, 0x02, 0x07, // address [1]
        ],
        "the octets are pinned: {encoded:02x?}"
    );
}

#[test]
fn an_address_round_trips_through_its_encoding() {
    for addr in [
        v4([192, 0, 2, 7]),
        HostAddress::of(SocketAddr::from((
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            0,
        ))),
    ] {
        let encoded = addr.encode();
        let mut r = der::Reader::new(&encoded);
        let content = r.expect_in("HostAddress", der::SEQUENCE).unwrap();
        assert_eq!(
            HostAddress::decode(content).unwrap(),
            addr,
            "type {} must survive",
            addr.addr_type
        );
    }
}

#[test]
fn caddr_round_trips_as_a_sequence_of_addresses() {
    let addresses = vec![v4([192, 0, 2, 7]), v4([198, 51, 100, 9])];
    let encoded = encode_caddr(&addresses);
    let back = decode_caddr(&encoded).unwrap();
    assert_eq!(back, addresses);
    assert_eq!(
        back.iter()
            .filter_map(HostAddress::socket_ip)
            .collect::<Vec<_>>(),
        vec![
            IpAddr::from([192, 0, 2, 7]),
            IpAddr::from([198, 51, 100, 9])
        ]
    );
}

#[test]
fn a_literal_host_resolves_to_itself_and_nothing_else() {
    // No lookup, so this is the case that must work on a machine with no resolver at all.
    let addrs = of_host("192.0.2.7", false).unwrap();
    assert_eq!(addrs, vec![v4([192, 0, 2, 7])]);
    let addrs = of_host("::1", false).unwrap();
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].addr_type, ADDRTYPE_INET6);
    let addrs = of_host("2001:db8::1", false).unwrap();
    assert_eq!(addrs[0].address.len(), 16);
}

#[test]
fn block_dns_refuses_a_name_rather_than_resolving_it() {
    // MIT's `block_dns`: a name resolved in a security path is a network dependency an attacker on
    // the resolver can answer. A refusal is the behaviour; a lookup here would be a vulnerability.
    let err = of_host("localhost", true).unwrap_err().to_string();
    assert!(err.contains("block_dns"), "{err}");
    assert!(
        of_host("127.0.0.1", true).is_ok(),
        "a literal is still accepted"
    );
}

#[test]
fn a_localhost_name_resolves_to_loopback_and_deduplicates() {
    // The one name a test can resolve without a network: every resolver has it.
    let addrs = of_host("localhost", false).unwrap();
    assert!(!addrs.is_empty());
    let mut seen = addrs.clone();
    seen.sort_by_key(|a| (a.addr_type, a.address.clone()));
    seen.dedup();
    assert_eq!(seen.len(), addrs.len(), "no duplicate address: {addrs:?}");
    for a in &addrs {
        assert!(
            matches!(a.addr_type, ADDRTYPE_INET | ADDRTYPE_INET6),
            "only the two types this crate emits: {a:?}"
        );
        assert!(matches!(a.address.len(), 4 | 16));
    }
}

#[test]
fn the_tgs_body_carries_caddr_only_when_there_are_addresses() {
    // A request with no addresses must not gain an empty `caddr`: the field is OPTIONAL, and a KDC
    // reading an empty sequence as "no addresses allowed" would refuse every ticket.
    let c = KdcClient::new("EXAMPLE.COM", ["127.0.0.1:88"]);
    let times = ReqTimes {
        from: None,
        till: 1_700_003_600,
        rtime: None,
    };
    let body = c.req_body_with(
        None,
        &Principal::krbtgt("EXAMPLE.COM"),
        1,
        &times,
        &[18],
        0,
        None,
        &[],
    );
    assert!(
        !body.windows(2).any(|w| w == [0xa8, 0x00]),
        "no empty caddr in the body: {body:02x?}"
    );

    let body = c.req_body_with(
        None,
        &Principal::krbtgt("EXAMPLE.COM"),
        1,
        &times,
        &[18],
        0,
        None,
        &[v4([192, 0, 2, 7])],
    );
    let mut r = der::Reader::new(&body);
    let content = r.expect_in("KDC-REQ-BODY", der::SEQUENCE).unwrap();
    let f = der::Fields::parse("KDC-REQ-BODY", content).unwrap();
    // `bytes` would hand back the whole TLV; `caddr` is a SEQUENCE, so the content is what
    // `decode_caddr` wants.
    // `addresses` is field [9]; [8] is `etype`, and reading that one would compare an enctype
    // list against an address list and pass on any body at all.
    let caddr = f
        .bytes(9, "KDC-REQ-BODY")
        .expect("addresses [9] is present");
    assert!(
        f.opt_bytes(8).is_some(),
        "the enctypes are still in [8], untouched"
    );
    assert_eq!(caddr[0], der::SEQUENCE, "caddr is a SEQUENCE");
    let decoded = decode_caddr(caddr).unwrap();
    assert_eq!(decoded, vec![v4([192, 0, 2, 7])]);
}

#[test]
fn a_krb_cred_carries_the_ticket_and_opens_with_the_key_it_was_sealed_under() {
    // The acceptance the whole path exists for: the peer holds only the session key, and must get
    // the ticket and its session key back out of the KRB-CRED.
    let key = Key::random(18).unwrap();
    let creds = fixture_credentials();
    let packed = creds.to_krb_cred(&key).unwrap();
    let back = crate::client::krbcred::decode(&packed, &[&key]).unwrap();
    assert_eq!(back.server, creds.server);
    assert_eq!(back.client, creds.client);
    assert_eq!(back.ticket, creds.ticket);
    assert_eq!(back.endtime, creds.endtime);
    assert_eq!(
        back.session_key, creds.session_key,
        "the peer needs the session key, not only the ticket"
    );
}

#[test]
fn a_krb_cred_does_not_open_with_a_key_it_was_not_sealed_under() {
    let key = Key::random(18).unwrap();
    let other = Key::random(18).unwrap();
    let packed = fixture_credentials().to_krb_cred(&key).unwrap();
    assert!(
        crate::client::krbcred::decode(&packed, &[&other]).is_err(),
        "another key of the same enctype must not open it"
    );
}

/// A `Credentials` with a ticket a decoder will accept, built here rather than obtained: the
/// properties under test are the KRB-CRED envelope and the address encoding, not the exchange.
fn fixture_credentials() -> Credentials {
    let server = Principal::parse("host/peer.example.com@EXAMPLE.COM").unwrap();
    let client = Principal::parse("alice@EXAMPLE.COM").unwrap();
    let session_key = Key::random(18).unwrap();
    let part = der::seq(&[
        der::field(0, der::flags32(FORWARDABLE)),
        der::field(1, encode_key(&session_key)),
        der::field(2, der::general_string("EXAMPLE.COM")),
        der::field(3, client.encode_name()),
        der::field(4, der::time(1_700_000_000)),
        der::field(5, der::time(1_700_000_000)),
        der::field(7, der::time(1_700_003_600)),
    ]);
    // Sealed under a key nobody in the test holds: the KRB-CRED carries the ticket verbatim.
    let service_key = Key::random(18).unwrap();
    let cipher = service_key.encrypt(2, &part).unwrap();
    let ticket = der::cons(
        der::app(1),
        &[der::seq(&[
            der::field(0, der::int(5)),
            der::field(1, der::general_string("EXAMPLE.COM")),
            der::field(2, server.encode_name()),
            der::field(3, encode_encrypted_data(18, &cipher)),
        ])],
    );
    Credentials {
        client,
        server,
        session_key,
        ticket,
        ticket_enctype: 18,
        flags: FORWARDABLE,
        authtime: 1_700_000_000,
        starttime: None,
        endtime: 1_700_003_600,
        renew_till: None,
    }
}
