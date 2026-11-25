//! User-to-user (RFC 4120 §2.9.2, MIT's `kvno --u2u`): a ticket a server
//! decrypts with the session key of its own TGT rather than a long-term
//! key, for servers that have no keytab (a user's desktop, say). The
//! server sends its TGT's ticket to the client, the client asks the KDC
//! for a ticket encrypted in that TGT's session key (ENC-TKT-IN-SKEY,
//! with the TGT as the additional ticket), and the server accepts it with
//! [`KerberosContext::accept_token_u2u`] or
//! [`KerberosContext::accept_ap_req_u2u`].
//!
//! [`KerberosContext::accept_token_u2u`]: crate::KerberosContext::accept_token_u2u
//! [`KerberosContext::accept_ap_req_u2u`]: crate::KerberosContext::accept_ap_req_u2u

use super::*;

/// KDCOptions enc-tkt-in-skey (bit 28).
const KDC_OPT_ENC_TKT_IN_SKEY: u32 = 1 << 3;

impl KdcClient {
    /// A user-to-user ticket for `server`, encrypted in the session key of
    /// `server_tgt` (the server's TGT, its ticket as the server sent it;
    /// the session key stays with the server), through `tgt`, the client's
    /// own TGT. The KDC issues it only if `server` is the client of
    /// `server_tgt` (or an alias of it) and the server allows duplicate
    /// session keys (MIT's `allow_dup_skey`, on by default).
    ///
    /// `server` with an empty realm is in `tgt`'s realm. Both TGTs must be
    /// for that realm: cross-realm user-to-user is not supported.
    pub fn user_to_user(
        &self,
        tgt: &Credentials,
        server: &Principal,
        server_tgt: &[u8],
    ) -> Result<Credentials> {
        block_on(self.user_to_user_on(&Blocking, tgt, server, server_tgt))
    }

    pub(crate) async fn user_to_user_on<N: Net>(
        &self,
        net: &N,
        tgt: &Credentials,
        server: &Principal,
        server_tgt: &[u8],
    ) -> Result<Credentials> {
        let realm = tgt_realm(tgt).to_string();
        let mut server = server.clone();
        if server.realm.is_empty() {
            server.realm = realm.clone();
        }
        let theirs = ticket_server(server_tgt)
            .ok_or_else(|| ClientError::Protocol("the server's TGT does not parse".into()))?;
        if !same_principal(&theirs, &Principal::krbtgt(&realm)) || server.realm != realm {
            return Err(ClientError::Protocol(format!(
                "user-to-user with {server}, whose TGT is for {theirs}, through a TGT for \
                 {realm}: cross-realm user-to-user is not supported"
            )));
        }
        self.tgs_ext(
            net,
            &realm,
            tgt,
            &server,
            KDC_OPT_ENC_TKT_IN_SKEY,
            Extra {
                s4u: &S4u::UserToUser(server_tgt),
                addresses: &[],
            },
        )
        .await
        .map(|r| r.creds)
    }
}

/// The server a Ticket names (its realm and sname).
pub(super) fn ticket_server(ticket: &[u8]) -> Option<Principal> {
    let tf = Fields::parse_tagged("Ticket", app(1), ticket).ok()?;
    let realm = tf.get(1).ok()?.string().ok()?;
    Principal::decode_name(tf.get(2).ok()?, realm).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Ticket` with a realm and a name: `[APPLICATION 1] SEQUENCE { [0] tkt-vno, [1] realm,
    /// [2] sname, ... }`. Only the two fields this file reads are filled - the encrypted part is
    /// opaque to the client, which is the whole reason a user-to-user ticket can be handed around.
    fn ticket(realm: &str, name: &[&str]) -> Vec<u8> {
        let mut parts = vec![der::field(0, der::int(5))];
        parts.push(der::field(1, der::general_string(realm)));
        let mut encoded = Vec::new();
        for piece in name {
            encoded.extend(der::general_string(piece));
        }
        // NT-SRV-INST, the name type a `krbtgt/REALM` carries (RFC 4120 §6.2).
        parts.push(der::field(
            2,
            der::seq(&[
                der::field(0, der::int(2)),
                der::field(1, der::seq(&[encoded])),
            ]),
        ));
        der::cons(app(1), &[der::seq(&parts)])
    }

    /// A server's TGT names `krbtgt/<REALM>@<REALM>`; that is the fact the cross-realm check is
    /// built on, so the reader that produces it earns its own test.
    #[test]
    fn the_ticket_names_its_realm_and_server() {
        let parsed = ticket_server(&ticket("AD.EXAMPLE.COM", &["krbtgt", "AD.EXAMPLE.COM"]))
            .expect("a well-formed ticket parses");
        assert_eq!(parsed.realm, "AD.EXAMPLE.COM");
        assert_eq!(parsed.components, vec!["krbtgt", "AD.EXAMPLE.COM"]);
    }

    /// Anything that is not a ticket is `None`, not a panic: the bytes come from another process.
    #[test]
    fn a_ticket_that_does_not_parse_is_none() {
        assert!(ticket_server(&[]).is_none());
        assert!(ticket_server(b"not a ticket").is_none());
        // The right tag over an empty body: a real shape with nothing in it.
        assert!(ticket_server(&der::cons(app(1), &[der::seq(&[])])).is_none());
    }

    /// The client's own TGT for `realm`, which every refusal below is made through.
    ///
    /// The KDC address does not resolve, and that is deliberate: each of these tests has to show
    /// that the decision was made *before* the request. If one of them gets as far as the network,
    /// the error says so and the assertion that names the refusal fails.
    fn client(realm: &str) -> KdcClient {
        KdcClient::new(realm, ["kdc.invalid"])
    }

    /// The client's TGT as a value: the exchange reads its server and session key, not its tickets.
    fn own_tgt(realm: &str) -> Credentials {
        Credentials {
            client: Principal::parse(&format!("user@{realm}")).unwrap(),
            server: Principal::krbtgt(realm),
            session_key: Key::new(18, vec![3; 32]).unwrap(),
            ticket: vec![],
            ticket_enctype: 18,
            flags: 0,
            authtime: 0,
            starttime: None,
            endtime: 0,
            renew_till: None,
        }
    }

    /// The check that runs before any network call, and the reason it exists: a server's TGT for
    /// another realm names a `krbtgt` that is not this realm's, so a ticket encrypted in its session
    /// key could not be accepted here. Refused by name rather than sent to the KDC to fail there.
    ///
    /// The server's own realm is this one; only its TGT is foreign. Isolating the two clauses this
    /// way is what makes the test able to see the `||` between them being turned into `&&`: with
    /// both clauses true a mutated condition still refuses, and the test would pass for the wrong
    /// reason.
    #[test]
    fn a_server_tgt_for_another_realm_is_refused_before_the_request() {
        let elsewhere = ticket("OTHER.EXAMPLE.NET", &["krbtgt", "OTHER.EXAMPLE.NET"]);

        let error = block_on(client("AD.EXAMPLE.COM").user_to_user_on(
            &Blocking,
            &own_tgt("AD.EXAMPLE.COM"),
            &Principal::parse("host@AD.EXAMPLE.COM").unwrap(),
            &elsewhere,
        ))
        .expect_err("a TGT for another realm cannot carry this exchange");
        let text = error.to_string();
        assert!(
            text.contains("cross-realm user-to-user is not supported"),
            "{text}"
        );
        assert!(
            text.contains("OTHER.EXAMPLE.NET"),
            "the reason names the realm: {text}"
        );
    }

    /// The other clause, isolated: the server's TGT is this realm's, and the server asked for is in
    /// another realm. Refused for the same reason, and the second half of the condition is what
    /// says so.
    #[test]
    fn a_server_in_another_realm_is_refused_before_the_request() {
        let ours = ticket("AD.EXAMPLE.COM", &["krbtgt", "AD.EXAMPLE.COM"]);

        let error = block_on(client("AD.EXAMPLE.COM").user_to_user_on(
            &Blocking,
            &own_tgt("AD.EXAMPLE.COM"),
            &Principal::parse("host@OTHER.EXAMPLE.NET").unwrap(),
            &ours,
        ))
        .expect_err("a server in another realm cannot be reached through this TGT");
        assert!(
            error
                .to_string()
                .contains("cross-realm user-to-user is not supported"),
            "{error}"
        );
    }

    /// With both sides in one realm the check lets the exchange through, and this is the test that
    /// says so: it must reach the network, where the unresolvable KDC is the failure. A condition
    /// that refused unconditionally - the shape a deleted `!` or an inverted `!=` produces - would
    /// answer here with the cross-realm message instead, and the assertion below would see it.
    #[test]
    fn a_matching_tgt_and_realm_are_not_refused_by_the_check() {
        let ours = ticket("AD.EXAMPLE.COM", &["krbtgt", "AD.EXAMPLE.COM"]);

        let error = block_on(client("AD.EXAMPLE.COM").user_to_user_on(
            &Blocking,
            &own_tgt("AD.EXAMPLE.COM"),
            &Principal::parse("host@AD.EXAMPLE.COM").unwrap(),
            &ours,
        ))
        .expect_err("the KDC address does not resolve, so the exchange cannot finish");
        let text = error.to_string();
        assert!(
            !text.contains("cross-realm"),
            "the exchange was refused by the realm check, which should have let it through: {text}"
        );
    }

    /// The server's TGT is not a TGT at all: refused as a protocol error, not as a lookup failure.
    #[test]
    fn a_server_tgt_that_is_not_a_ticket_is_refused() {
        let client = KdcClient::new("AD.EXAMPLE.COM", ["kdc.ad.example.com"]);
        let tgt = Credentials {
            client: Principal::parse("user@AD.EXAMPLE.COM").unwrap(),
            server: Principal::krbtgt("AD.EXAMPLE.COM"),
            session_key: Key::new(18, vec![3; 32]).unwrap(),
            ticket: vec![],
            ticket_enctype: 18,
            flags: 0,
            authtime: 0,
            starttime: None,
            endtime: 0,
            renew_till: None,
        };
        let error = block_on(client.user_to_user_on(
            &Blocking,
            &tgt,
            &Principal::parse("host@AD.EXAMPLE.COM").unwrap(),
            b"garbage",
        ))
        .expect_err("bytes that are not a ticket cannot carry this exchange");
        assert!(error.to_string().contains("does not parse"), "{error}");
    }

    /// `KDCOptions` bit 28 of RFC 4120 §5.4.1, as the option word counts from zero: the KDC issues
    /// a ticket in the session key of another ticket for this bit and nothing else. A wrong bit
    /// would be accepted by the KDC as some other option and give a ticket the server cannot open.
    #[test]
    fn the_option_bit_is_the_one_rfc_4120_names() {
        assert_eq!(KDC_OPT_ENC_TKT_IN_SKEY, 1 << 3);
    }
}
