//! kx509 client (RFC 6717): trade a ticket for an X.509 certificate.
//!
//! A client that already holds a ticket asks the KDC for a certificate naming the principal that
//! ticket proves, and gets one signed by the realm's authority. The ticket is the whole credential —
//! no password, no keytab, no second login — which is the point: a host that can `kinit` can also
//! authenticate to a TLS endpoint that only knows X.509.
//!
//! **The request is not a `KDC-REQ`.** It begins with four version octets, so it travels to the same
//! port and through the same transport: the same four-octet length prefix of RFC 4120 §7.2.2, which
//! is how a server tells the two apart before decoding either. The wire format — both directions and
//! both MACs — lives in [`rrl_krb_common::kx509`], shared with the KDC, because a second encoder
//! would be a second way to disagree about a MAC that has no room for interpretation.
//!
//! **What this module does and does not do.** It builds the request, sends it, checks the reply MAC
//! and hands back the certificate's DER. It does *not* validate the certificate: whether the chain
//! reaches a trust anchor, whether the name inside matches the principal, and whether the realm's
//! authority is to be believed are all questions for an X.509 verifier, and a Kerberos client that
//! answered them itself would be a second, worse implementation of one.
//!
//! **The MAC is the authentication of the payload.** The AP-REQ says who is asking; the MAC over
//! `version || pk-key`, keyed with the ticket's session key, says that whoever built this request
//! holds that key. A relay that paired somebody else's ticket with its own CSR fails there, and a
//! reply whose MAC does not verify is refused rather than reported as an error code — a client must
//! not let a relay turn "here is your certificate" into anything else.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rrl_krb_common::kx509::{self, Request, Response, plus_from_csr};

use crate::client::{ClientError, Credentials, encode_ap_req, encode_authenticator};
use crate::key::Key;
use crate::net::{Blocking, Net, block_on};

/// RFC 4120 §7.5.1: the authenticator, sealed in the ticket's session key.
const KU_AP_REQ_AUTH: u32 = 11;
use crate::Principal;

/// The service component a kx509 ticket must name.
///
/// The KDC checks the first component and the realm, not the whole name, so a client asks for
/// `kx509/HOST@REALM` with whatever host it was told the service lives at — which for a realm whose
/// KDC answers kx509 itself is the realm's own name.
pub const SERVICE: &str = "kx509";

/// How long a connect, a write and a read may take before the attempt is abandoned.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The largest reply this client will read: a certificate chain, not a stream.
const MAX_REPLY: usize = 1 << 20;

/// The principal a kx509 ticket has to be for: `kx509/HOST@REALM`.
pub fn service(realm: &str, host: &str) -> Result<Principal, ClientError> {
    Principal::parse(&format!("{SERVICE}/{host}@{realm}"))
}

/// The DER of a `Kx509Request` for `csr`, authenticated by `creds`' ticket.
///
/// The CSR is wrapped in a `Kx509CSRPlus`; a caller that passes the CSR's DER gets the proof of
/// possession the server needs, because the signature inside the CSR is that proof. Handing the
/// server a bare public key instead is refused by the shared code for the format, and by name.
pub fn request(creds: &Credentials, csr: &[u8]) -> Result<Vec<u8>, ClientError> {
    let authenticator = ap_req(creds)?;
    let mut request = Request {
        authenticator,
        pk_hash: Vec::new(),
        pk_key: plus_from_csr(csr),
    };
    // Computed from the finished request, so the MAC covers exactly what travels: an encoder that
    // assembled the same fields in a second place could disagree with itself.
    request.pk_hash = request.mac(creds.session_key.bytes());
    Ok(request.encode())
}

/// The AP-REQ that names the ticket, sealed in the ticket's session key.
///
/// Mutual authentication is not asked for: the reply is a certificate, so there is nothing an
/// AP-REP would add, and a server that sent one anyway would be sending bytes nobody reads.
fn ap_req(creds: &Credentials) -> Result<Vec<u8>, ClientError> {
    let (ctime, cusec) = now();
    let authenticator = encode_authenticator(&creds.client, None, cusec, ctime, None, None, None);
    let sealed = creds
        .session_key
        .encrypt(KU_AP_REQ_AUTH, &authenticator)
        .map_err(ClientError::from)?;
    Ok(encode_ap_req(
        0,
        &creds.ticket,
        creds.session_key.enctype(),
        &sealed,
    ))
}

/// The certificate out of a `Kx509Response`, or the reason there is none.
///
/// `session_key` is the ticket's session key: the reply MAC is keyed with it, so a reply that does
/// not verify is refused here, before any of it is believed.
pub fn certificate(response: &[u8], session_key: &Key) -> Result<Vec<u8>, ClientError> {
    let response = Response::decode(response)
        .map_err(|e| ClientError::Protocol(format!("kx509 response: {e}")))?;
    if response.error_code != 0 {
        return Err(ClientError::Kx509 {
            code: response.error_code,
            text: response.text.clone(),
        });
    }
    // A response past authentication always carries a MAC; one that does not is not this KDC's.
    if response.hash.is_none() {
        return Err(ClientError::Protocol(
            "the kx509 response carries no MAC, so nothing in it can be believed".into(),
        ));
    }
    if !response.verify_mac(session_key.bytes()) {
        return Err(ClientError::Protocol(
            "the kx509 response MAC does not verify: it was not built by the holder of this \
             ticket's session key"
                .into(),
        ));
    }
    response
        .certificate
        .ok_or_else(|| ClientError::Protocol("the kx509 response carries no certificate".into()))
}

/// Asks `server` (`host:port`) for a certificate for `csr`, over the transport the KDC speaks.
pub fn fetch(creds: &Credentials, csr: &[u8], server: &str) -> Result<Vec<u8>, ClientError> {
    block_on(fetch_on(&Blocking, creds, csr, server))
}

/// [`fetch`] over any [`Net`], so the same exchange runs on the async client's sockets.
pub(crate) async fn fetch_on<N: Net>(
    net: &N,
    creds: &Credentials,
    csr: &[u8],
    server: &str,
) -> Result<Vec<u8>, ClientError> {
    let request = request(creds, csr)?;
    let addr = net
        .resolve(server)
        .await
        .and_then(|addrs| {
            addrs
                .first()
                .copied()
                .ok_or_else(|| std::io::Error::other(format!("{server}: no address")))
        })
        .map_err(|last| ClientError::Unreachable {
            realm: creds.client.realm.clone(),
            last,
        })?;
    let mut stream = net
        .connect(addr, TIMEOUT)
        .await
        .map_err(|last| ClientError::Unreachable {
            realm: creds.client.realm.clone(),
            last,
        })?;
    // RFC 4120 §7.2.2's framing, the same one a KDC-REQ gets: the port cannot tell the two apart
    // without it, and a kx509 request is a message on that port.
    let mut framed = (request.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&request);
    net.write_all(&mut stream, &framed, TIMEOUT)
        .await
        .map_err(|last| ClientError::Unreachable {
            realm: creds.client.realm.clone(),
            last,
        })?;

    let mut len = [0u8; 4];
    net.read_exact(&mut stream, &mut len, TIMEOUT)
        .await
        .map_err(|last| ClientError::Unreachable {
            realm: creds.client.realm.clone(),
            last,
        })?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_REPLY {
        return Err(ClientError::Protocol(format!(
            "the kx509 reply claims {len} octets, which is not a certificate chain"
        )));
    }
    let mut body = vec![0u8; len];
    net.read_exact(&mut stream, &mut body, TIMEOUT)
        .await
        .map_err(|last| ClientError::Unreachable {
            realm: creds.client.realm.clone(),
            last,
        })?;
    certificate(&body, &creds.session_key)
}

/// Wall-clock time as Kerberos states it: seconds and microseconds since the epoch.
fn now() -> (i64, u32) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_micros()),
        Err(_) => (0, 0),
    }
}

/// The shared crate's constants, re-exported so a caller of this module does not have to know which
/// crate the protocol lives in.
pub use rrl_krb_common::kx509::{KRB_ERROR_BASE, STATUS_CLIENT_BAD, STATUS_SERVER_BAD, VERSION};

// Keeps the import above honest: `kx509` itself is used for the module's own documentation path.
const _: [u8; 4] = kx509::VERSION;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Key;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A ticket and its session key, as `kadmin` would hand them over: the ticket's octets are
    /// opaque here because the fake KDC below never opens them.
    fn credentials(key: &Key) -> Credentials {
        Credentials {
            client: Principal::parse("alice@EXAMPLE.COM").unwrap(),
            server: Principal::parse("kx509/EXAMPLE.COM@EXAMPLE.COM").unwrap(),
            session_key: key.clone(),
            ticket: b"a TGT for kx509/EXAMPLE.COM".to_vec(),
            ticket_enctype: key.enctype(),
            flags: 0,
            authtime: 0,
            starttime: None,
            endtime: 4_000_000_000,
            renew_till: None,
        }
    }

    fn session_key() -> Key {
        Key::new(18, vec![0x5a; 32]).expect("an AES-256 key")
    }

    /// A stand-in for the KDC: one connection, one request, one answer built by `answer`.
    ///
    /// `answer` gets the request and the session key and returns the response's octets, so a test
    /// can shape a good reply, a wrong MAC, an error or a missing certificate without a second
    /// implementation of the protocol.
    fn serve<F>(answer: F) -> String
    where
        F: FnOnce(&Request, &Key) -> Vec<u8> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a connection");
            let mut len = [0u8; 4];
            stream.read_exact(&mut len).expect("a length");
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            stream.read_exact(&mut body).expect("a request");
            let request = Request::decode(&body).expect("a kx509 request");
            let reply = answer(&request, &session_key());
            let mut framed = (reply.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(&reply);
            stream.write_all(&framed).expect("a reply");
        });
        addr.to_string()
    }

    /// The MAC the server side would compute for a successful answer.
    fn good_response(certificate: &[u8], key: &Key) -> Vec<u8> {
        let mut response = Response {
            error_code: 0,
            hash: None,
            certificate: Some(certificate.to_vec()),
            text: None,
        };
        response.hash = Some(response.mac(key.bytes()));
        response.encode()
    }

    /// The whole chain: the request carries the CSR in a `Kx509CSRPlus`, its MAC verifies under the
    /// session key, and the reply's certificate comes back.
    #[test]
    fn a_request_is_built_and_its_certificate_read_back() {
        let key = session_key();
        let creds = credentials(&key);
        let csr = b"a CSR, in DER";

        let sent = request(&creds, csr).expect("a request");
        assert!(Request::claims(&sent));
        let decoded = Request::decode(&sent).expect("decodes");
        assert_eq!(
            rrl_krb_common::kx509::csr_from_plus(&decoded.pk_key).expect("a CSR"),
            csr
        );
        // The AP-REQ names the ticket, and nothing of the session key is in the clear.
        assert!(!decoded.authenticator.is_empty());
        assert!(
            decoded.verify_mac(key.bytes()),
            "the request MAC is keyed with the ticket's session key"
        );

        let issued = b"a certificate, in DER";
        let reply = good_response(issued, &key);
        assert_eq!(certificate(&reply, &key).expect("the certificate"), issued);
    }

    /// A reply that was not built by the holder of the session key is refused, and the refusal says
    /// which check failed: this is the one thing that keeps a relay from handing over a certificate.
    #[test]
    fn a_reply_with_a_wrong_mac_is_refused() {
        let key = session_key();
        let reply = good_response(b"a certificate", &Key::new(18, vec![0x00; 32]).unwrap());
        let err = certificate(&reply, &key).expect_err("a foreign MAC must be refused");
        assert!(err.to_string().contains("MAC does not verify"), "{err}");
    }

    /// A reply with no MAC at all is refused even when it carries a certificate: "the server said
    /// nothing about who it is" is not an answer.
    #[test]
    fn a_reply_without_a_mac_is_refused() {
        let key = session_key();
        let reply = Response {
            error_code: 0,
            hash: None,
            certificate: Some(b"a certificate".to_vec()),
            text: None,
        }
        .encode();
        let err = certificate(&reply, &key).expect_err("no MAC, no certificate");
        assert!(err.to_string().contains("carries no MAC"), "{err}");
    }

    /// An error answer is reported with its own code and text — kx509's numbering, not RFC 4120's.
    #[test]
    fn an_error_answer_carries_its_code_and_text() {
        let key = session_key();
        let reply = Response::error(
            KRB_ERROR_BASE + 24,
            "the ticket is for kx509/EXAMPLE.COM, and the request MAC does not verify",
        )
        .encode();
        match certificate(&reply, &key) {
            Err(ClientError::Kx509 { code, text }) => {
                assert_eq!(code, KRB_ERROR_BASE + 24);
                assert!(text.unwrap().contains("does not verify"));
            }
            other => panic!("expected a kx509 error, got {other:?}"),
        }
    }

    /// End to end over a socket: the request goes out with RFC 4120's framing and the certificate
    /// comes back through the same exchange a real KDC would answer.
    #[test]
    fn a_fetch_over_a_socket_returns_the_certificate() {
        let key = session_key();
        let creds = credentials(&key);
        let certificate_der = b"a certificate, in DER".to_vec();
        let expected = certificate_der.clone();
        let server = serve(move |request, key| {
            assert!(
                request.verify_mac(key.bytes()),
                "the server can verify what the client signed"
            );
            good_response(&expected, key)
        });

        let got = fetch(&creds, b"a CSR, in DER", &server).expect("the certificate");
        assert_eq!(got, certificate_der);
    }

    /// A reply that claims more octets than a certificate chain could hold is refused before it is
    /// read, rather than allocated: the length is the server's word, and it is not taken on trust.
    #[test]
    fn an_absurd_reply_length_is_refused() {
        let key = session_key();
        let creds = credentials(&key);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut len = [0u8; 4];
            let _ = stream.read_exact(&mut len);
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            let _ = stream.read_exact(&mut body);
            let _ = stream.write_all(&(u32::MAX).to_be_bytes());
        });
        let err = fetch(&creds, b"a CSR", &addr.to_string()).expect_err("a bogus length");
        assert!(err.to_string().contains("octets"), "{err}");
    }

    /// The service name a client asks a ticket for is `kx509/HOST@REALM`; the realm is the one it
    /// belongs to, which is what the KDC checks.
    #[test]
    fn the_service_is_kx509_under_the_realms_name() {
        let principal = service("EXAMPLE.COM", "EXAMPLE.COM").unwrap();
        assert_eq!(principal.to_string(), "kx509/EXAMPLE.COM@EXAMPLE.COM");
    }
}
