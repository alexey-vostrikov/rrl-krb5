//! The GSS-API mechanism layer: one interface over "however this connection authenticates".
//!
//! An application that speaks HTTP `Negotiate`, SMB or LDAP SASL asks for a security context, not
//! for Kerberos. Everything above this module — an HTTP server, a CIFS client, a SASL state machine —
//! should be able to say "authenticate this connection" and get a context back without knowing which
//! mechanism did it, and adding a mechanism should not touch those callers at all.
//!
//! That is the whole point of the layer, and it is what was missing: [`InitiatorContext`] and
//! [`KerberosContext`] are Kerberos-specific by construction, and [`crate::spnego`] hard-codes
//! Kerberos in its negotiation (`is_krb5`). Both are correct at their level; neither is a place an
//! application can hold.
//!
//! # What the layer is, in GSS terms
//!
//! * [`Mechanism`] — an OID and the two ways to create a context, `gss_init_sec_context`'s and
//!   `gss_accept_sec_context`'s.
//! * [`Context`] — one object per connection: [`Context::step`], [`Context::is_established`],
//!   [`Context::flags`], [`Context::per_message`]. The application never sees which mechanism it is.
//! * [`Registry`] — the mechanisms this build has, in preference order: `gss_indicate_mechs`, and the
//!   dispatch that reads a peer's token and finds the mechanism it names.
//!
//! # OIDs are content octets, not framed DER
//!
//! [`Mechanism::oids`] returns the nine content octets of `1.2.840.113554.1.2.2` and compares them
//! against the OID a peer's token carries, parsed out of the DER. The alternative — carrying the OID
//! with its tag and length — compares lengths as well as identities, so an OID re-encoded with a
//! different length form reads as a mechanism we do not have. DER canonicalises the length, so the
//! two are equivalent *given correct code*; the point is to not depend on that.
//!
//! # What this layer deliberately does not do
//!
//! * **It does not negotiate.** SPNEGO's state machine stays in [`crate::spnego`], where the MICs and
//!   the NegTokenInit/Resp rules already are; [`Registry::select`] is the piece it would consume when
//!   a second mechanism exists to negotiate between.
//! * **It has no IAKERB** (RFC-less `draft-ietf-cat-iakerb`). Heimdal does not implement it either —
//!   two OIDs and two unused error codes — and the proxy it needs is infrastructure, not a KDC or a
//!   client library. A mechanism registered here later would be the place for it.
//! * **It does not enforce per-message sequence order.** [`crate::token::Verified::seq`] is returned
//!   and the caller decides: under RPCSEC_GSS, RFC 2203 §5.2.2 requires ordering checks to be off at
//!   this layer, and a library that insisted would break the one protocol that uses these tokens most.
//!
//! # One round, or many
//!
//! Kerberos completes in one round trip: the initiator's first token is the `AP-REQ`, and the
//! acceptor's answer is the `AP-REP` when mutual authentication was asked for. [`Context::step`]
//! exists for the mechanisms that need more — a SPAKE or a token exchange — so that a caller written
//! once keeps working when one is added.

use std::cell::{Cell, OnceCell};
use std::fmt;

use crate::acceptor::{KerberosContext, KerberosError, Keytab};
use crate::client::{ClientError, Credentials};
use crate::der;
use crate::initiator::InitiatorContext;
use crate::token::{ContextKey, PerMessageTokens, Verified};

/// Everything the layer can refuse, from either side.
#[derive(Debug)]
pub enum GssError {
    /// The initiator side of a mechanism refused.
    Initiator(ClientError),
    /// The acceptor side of a mechanism refused.
    Acceptor(KerberosError),
    /// A mechanism named by an OID this build does not have.
    UnknownMechanism {
        /// The OID as dotted decimal, or its hexadecimal DER when it does not parse.
        oid: String,
        /// What this build does have, by name.
        have: Vec<&'static str>,
    },
    /// A request that needs at least one mechanism, on a registry with none.
    NoMechanisms,
    /// A token that is not a GSS initial context token: no `[APPLICATION 0]`, or no OID inside it.
    MalformedToken(&'static str),
    /// A token where the mechanism has nothing left to consume — Kerberos completes in one round.
    UnexpectedToken,
    /// Per-message tokens were asked for before the context was established.
    NotEstablished,
}

impl fmt::Display for GssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GssError::Initiator(e) => write!(f, "{e}"),
            GssError::Acceptor(e) => write!(f, "{e}"),
            GssError::UnknownMechanism { oid, have } => write!(
                f,
                "no mechanism with OID {oid} in this build; it has {have:?}. \
                 A peer may be offering a mechanism this crate does not implement"
            ),
            GssError::NoMechanisms => write!(
                f,
                "the registry has no mechanisms, so no context can be established: \
                 register one (Registry::with_krb5) before asking for a context"
            ),
            GssError::MalformedToken(why) => write!(f, "not a GSS initial context token: {why}"),
            GssError::UnexpectedToken => write!(
                f,
                "the mechanism has no further tokens to consume: Kerberos completes in one round, \
                 so a second token is a protocol error rather than something to ignore"
            ),
            GssError::NotEstablished => write!(
                f,
                "the context is not established yet, so it has no per-message keys"
            ),
        }
    }
}

impl std::error::Error for GssError {}

impl From<ClientError> for GssError {
    fn from(e: ClientError) -> Self {
        GssError::Initiator(e)
    }
}

impl From<KerberosError> for GssError {
    fn from(e: KerberosError) -> Self {
        GssError::Acceptor(e)
    }
}

impl From<crate::token::TokenError> for GssError {
    fn from(e: crate::token::TokenError) -> Self {
        // A per-message token failure is a failed unwrap, which on the accept side is what a bad
        // MIC or a truncated Wrap is: reported through the acceptor's error type so a caller has
        // one place to look.
        GssError::Acceptor(KerberosError::DecryptionFailed(e.to_string()))
    }
}

/// `1.2.840.113554.1.2.2`, as content octets — without the tag and length DER puts around them.
///
/// The identity of a mechanism is these nine octets. The framing is DER's business, and a registry
/// that compared framed OIDs would be comparing lengths as well as identities, which is how a
/// re-encoded OID comes to look like an unknown mechanism.
pub const KRB5: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];

/// `1.2.840.48018.1.2.2`: what Microsoft's clients send, as content octets.
///
/// It is an **alias of the same mechanism**, not a second one: Windows lists it first in its
/// mechanism list, MIT accepts it as Kerberos 5, and this crate's acceptor already accepts both. A
/// registry that treated it as separate would have two entries that build identical contexts.
pub const MS_KRB5: &[u8] = &[0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02];

/// An OID as dotted decimal, for a message a human reads.
///
/// `None` when the octets are not a decodable OID arc sequence: the caller then prints them as hex
/// rather than inventing a number that does not exist.
pub fn dotted_oid(content: &[u8]) -> Option<String> {
    der::decode_oid("mechanism OID", content).ok()
}

/// A context and the token to send next: `gss_init_sec_context`'s and `gss_accept_sec_context`'s
/// return shape, which both sides have and which a caller reads the same way either way.
///
/// `None` for the token means "nothing to send": the initiator always has one (its `AP-REQ`), an
/// acceptor has one only when the mechanism answers (Kerberos does, for mutual authentication).
pub type Established = (Box<dyn Context>, Option<Vec<u8>>);

/// A mechanism the layer can establish a context with.
///
/// Implementations are cheap values: the state of a connection lives in the [`Context`] they return,
/// so one `Mechanism` serves every connection on the server.
pub trait Mechanism: fmt::Debug + Send + Sync {
    /// The name a log line or an error should use: `krb5`, `spnego`, `ntlm`.
    fn name(&self) -> &'static str;

    /// The OIDs this mechanism answers to, as **content octets**, most preferred first.
    ///
    /// More than one means aliases of the same mechanism, not alternatives: a token naming any of
    /// them builds the same context.
    fn oids(&self) -> &'static [&'static [u8]];

    /// `gss_init_sec_context`, first call: the context and the token to send.
    fn initiator(
        &self,
        creds: &Credentials,
        flags: u32,
    ) -> Result<Established, GssError>;

    /// `gss_accept_sec_context`, first call: the context and the reply to send, if any.
    ///
    /// The token is the peer's, already framed — the layer dispatched on its OID to get here.
    fn accept(
        &self,
        keytab: &Keytab,
        token: &[u8],
    ) -> Result<Established, GssError>;
}

/// One established-or-establishing security context.
///
/// Object-safe on purpose: the application holds a `Box<dyn Context>` and never matches on the
/// mechanism. Anything it needs to know is a method here, which is why `client`/`service` exist even
/// though a mechanism without names in its protocol would return `None`.
pub trait Context: fmt::Debug + Send {
    /// The mechanism's name, for a log line.
    fn mechanism(&self) -> &'static str;

    /// The mechanism's primary OID, as content octets.
    fn mech_oid(&self) -> &[u8];

    /// Consumes a token from the peer, returning one to send back.
    ///
    /// `Ok(None)` and an established context mean the handshake is over.
    fn step(&mut self, token: &[u8]) -> Result<Option<Vec<u8>>, GssError>;

    /// Whether both sides have agreed on keys and the context can carry messages.
    fn is_established(&self) -> bool;

    /// The `GSS_C_*_FLAG`s the context actually has — not the ones that were asked for. A mechanism
    /// that cannot delegate drops `GSS_C_DELEG_FLAG`, and a caller that trusted its request would
    /// send a delegation it does not have.
    fn flags(&self) -> u32;

    /// The name the mechanism authenticated as the client, when its protocol has names.
    fn client(&self) -> Option<&str>;

    /// The name of the service that was authenticated, when its protocol has names.
    fn service(&self) -> Option<&str>;

    /// The RFC 4121 §4.2 per-message machinery, built once and kept.
    ///
    /// `Err(GssError::NotEstablished)` before the handshake finishes: the keys do not exist yet, and
    /// returning an object that would fail on first use would move the failure to a place with less
    /// context.
    fn per_message(&self) -> Result<&PerMessage, GssError>;
}

/// `gss_wrap` / `gss_unwrap` / `gss_get_mic` / `gss_verify_mic` over one context.
///
/// The send counter advances on every emitted token; the receive side reports the sequence number it
/// saw and does **not** enforce order, because RFC 2203 §5.2.2 requires the GSS layer to leave that
/// to RPC, which reorders. A caller that wants strict ordering compares [`Verified::seq`] itself.
pub struct PerMessage {
    tokens: PerMessageTokens<ContextKey>,
    send_seq: Cell<u64>,
}

impl fmt::Debug for PerMessage {
    /// The keys are not printed: a `Debug` that dumped them would put a context's session keys into
    /// whatever log a caller wrote it to.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PerMessage")
            .field("next_send_seq", &self.send_seq.get())
            .finish_non_exhaustive()
    }
}

impl PerMessage {
    fn new(tokens: PerMessageTokens<ContextKey>, send_seq: u64) -> Self {
        Self {
            tokens,
            send_seq: Cell::new(send_seq),
        }
    }

    /// The sequence number the next emitted token will carry.
    pub fn next_send_seq(&self) -> u64 {
        self.send_seq.get()
    }

    /// `gss_wrap` with confidentiality: the plaintext is encrypted.
    pub fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, GssError> {
        let seq = self.send_seq.get();
        let token = self.tokens.emit_wrap(seq, plaintext)?;
        self.send_seq.set(seq + 1);
        Ok(token)
    }

    /// `gss_wrap` without confidentiality: integrity only, which is what a caller sends when the
    /// payload is already protected or must stay readable to a middlebox.
    pub fn wrap_unsealed(&self, plaintext: &[u8]) -> Result<Vec<u8>, GssError> {
        let seq = self.send_seq.get();
        // `rrc` is the right-rotation count the sender chooses; zero is what a caller that does not
        // care passes, and RFC 4121 §4.2.4 has the receiver read it from the header either way.
        let token = self.tokens.emit_wrap_unsealed(seq, plaintext, 0)?;
        self.send_seq.set(seq + 1);
        Ok(token)
    }

    /// `gss_unwrap`: verifies the token and returns what it carried.
    pub fn unwrap(&self, token: &[u8]) -> Result<Verified, GssError> {
        Ok(self.tokens.unwrap(token)?)
    }

    /// `gss_unwrap` for a token that was wrapped without confidentiality.
    pub fn unwrap_unsealed(&self, token: &[u8]) -> Result<Verified, GssError> {
        Ok(self.tokens.verify_wrap_unsealed(token)?)
    }

    /// `gss_get_mic`: a token proving `message` came from this context.
    pub fn mic(&self, message: &[u8]) -> Result<Vec<u8>, GssError> {
        let seq = self.send_seq.get();
        let token = self.tokens.emit_mic(seq, message)?;
        self.send_seq.set(seq + 1);
        Ok(token)
    }

    /// `gss_verify_mic`.
    pub fn verify_mic(&self, token: &[u8], message: &[u8]) -> Result<Verified, GssError> {
        Ok(self.tokens.verify_mic(token, message)?)
    }
}

/// The mechanisms this build has, in preference order.
///
/// Order is a decision, and it is the realm's: [`Registry::first`] is what a caller gets when it asks
/// for a context without naming a mechanism, and [`Registry::select`] is what an acceptor uses when a
/// peer offers several.
#[derive(Debug, Default)]
pub struct Registry {
    mechanisms: Vec<Box<dyn Mechanism>>,
}

impl Registry {
    /// An empty registry.
    ///
    /// Empty rather than Kerberos-by-default: a build that registered a mechanism implicitly would
    /// answer a request it was never told to answer, and "no mechanisms" is a state an operator can
    /// see and fix.
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry with the Kerberos 5 mechanism, which is the one every deployment wants first.
    pub fn with_krb5() -> Self {
        Registry::new().register(Box::new(Krb5))
    }

    /// Adds `mechanism` at the end of the preference order.
    pub fn register(mut self, mechanism: Box<dyn Mechanism>) -> Self {
        self.mechanisms.push(mechanism);
        self
    }

    /// How many mechanisms there are.
    pub fn len(&self) -> usize {
        self.mechanisms.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.mechanisms.is_empty()
    }

    /// The mechanisms, in preference order.
    pub fn mechanisms(&self) -> impl Iterator<Item = &dyn Mechanism> {
        self.mechanisms.iter().map(AsRef::as_ref)
    }

    /// `gss_indicate_mechs`: every OID this build answers to, in preference order.
    ///
    /// Aliases appear here too. A peer that reads this list and offers the Microsoft OID first is
    /// telling us what it knows, and it must find it in the set.
    pub fn indicate_mechs(&self) -> Vec<&'static [u8]> {
        self.mechanisms
            .iter()
            .flat_map(|m| m.oids().iter().copied())
            .collect()
    }

    /// The mechanism that answers to `oid` (content octets), aliases included.
    pub fn find(&self, oid: &[u8]) -> Option<&dyn Mechanism> {
        self.mechanisms
            .iter()
            .find(|m| m.oids().contains(&oid))
            .map(AsRef::as_ref)
    }

    /// The mechanism a peer's offer picks: **the peer's order**, first we support.
    ///
    /// That is RFC 4178 §4.2.1's rule — the initiator's preference wins — and it differs from
    /// [`Self::first`] on purpose: a client that lists NTLM before Kerberos has said which it wants,
    /// and an acceptor that imposed its own order would silently authenticate a context the client
    /// was least willing to use.
    pub fn select(&self, offered: &[&[u8]]) -> Option<&dyn Mechanism> {
        offered.iter().find_map(|oid| self.find(oid))
    }

    /// The most preferred mechanism.
    pub fn first(&self) -> Option<&dyn Mechanism> {
        self.mechanisms.first().map(AsRef::as_ref)
    }

    /// `gss_init_sec_context`: a context over `mech`, or the most preferred one when it is `None`.
    ///
    /// `None` is `GSS_C_NO_OID`, the request an application makes when it does not care — which is
    /// most of them.
    pub fn initiator(
        &self,
        mech: Option<&[u8]>,
        creds: &Credentials,
        flags: u32,
    ) -> Result<Established, GssError> {
        let mechanism = match mech {
            Some(oid) => self.find(oid).ok_or_else(|| GssError::UnknownMechanism {
                oid: describe_oid(oid),
                have: self.names(),
            })?,
            None => self.first().ok_or(GssError::NoMechanisms)?,
        };
        mechanism.initiator(creds, flags)
    }

    /// `gss_accept_sec_context`: dispatches on the OID inside the peer's token.
    ///
    /// The OID is read from the token rather than passed in, because that is what the token is for:
    /// an acceptor that had to be told which mechanism to expect could not serve two kinds of client
    /// on one port, which is exactly what HTTP `Negotiate` and SMB do.
    pub fn acceptor(
        &self,
        keytab: &Keytab,
        token: &[u8],
    ) -> Result<Established, GssError> {
        let oid = token_mech(token)?;
        let mechanism = self.find(oid).ok_or_else(|| GssError::UnknownMechanism {
            oid: describe_oid(oid),
            have: self.names(),
        })?;
        mechanism.accept(keytab, token)
    }

    fn names(&self) -> Vec<&'static str> {
        self.mechanisms.iter().map(|m| m.name()).collect()
    }
}

/// `oid` as dotted decimal when it parses, hexadecimal when it does not.
fn describe_oid(oid: &[u8]) -> String {
    dotted_oid(oid).unwrap_or_else(|| {
        oid.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    })
}

/// The mechanism OID inside a GSS initial context token (`RFC 2743 §3.1`):
/// `[APPLICATION 0] { thisMech OID, innerContextToken }`.
///
/// Returns the OID **as it appears in the token**, framed, so a registry compares bytes.
fn token_mech(token: &[u8]) -> Result<&[u8], GssError> {
    let mut r = der::Reader::new(token);
    let body = r
        .expect(0x60)
        .map_err(|_| GssError::MalformedToken("the outer tag is not [APPLICATION 0]"))?;
    let mut inner = der::Reader::new(body);
    let oid = inner
        .next_tlv("initial context token")
        .map_err(|_| GssError::MalformedToken("no OID after the application tag"))?;
    if oid.tag != der::OBJECT_IDENTIFIER {
        return Err(GssError::MalformedToken(
            "the first field is not an OID, so the token names no mechanism",
        ));
    }
    Ok(oid.content)
}

/// The Kerberos 5 mechanism.
///
/// A unit struct: the connection's state is in the context, so a server keeps one of these for its
/// whole life. Both OIDs are declared — the standard one and the one Microsoft sends — because they
/// name the same mechanism and this crate's acceptor already accepts either.
#[derive(Debug, Clone, Copy, Default)]
pub struct Krb5;

impl Mechanism for Krb5 {
    fn name(&self) -> &'static str {
        "krb5"
    }

    fn oids(&self) -> &'static [&'static [u8]] {
        &[KRB5, MS_KRB5]
    }

    fn initiator(
        &self,
        creds: &Credentials,
        flags: u32,
    ) -> Result<Established, GssError> {
        let (ctx, token) = InitiatorContext::new(creds, flags)?;
        Ok((
            Box::new(Initiating {
                inner: ctx,
                per_message: OnceCell::new(),
            }),
            Some(token),
        ))
    }

    fn accept(
        &self,
        keytab: &Keytab,
        token: &[u8],
    ) -> Result<Established, GssError> {
        let (ctx, reply) = KerberosContext::accept_token(keytab, token)?;
        // Built before the context is moved into the adapter: the keys come from it.
        let per_message = build_per_message_accept(&ctx)?;
        Ok((
            Box::new(Accepting {
                inner: ctx,
                per_message,
            }),
            (!reply.is_empty()).then_some(reply),
        ))
    }
}

fn build_per_message_accept(ctx: &KerberosContext) -> Result<Option<PerMessage>, GssError> {
    if !ctx.established {
        return Ok(None);
    }
    let tokens = ctx.per_message_tokens()?;
    Ok(Some(PerMessage::new(tokens, u64::from(ctx.acceptor_seq))))
}

/// The initiator side of a Kerberos context, as the layer sees it.
#[derive(Debug)]
struct Initiating {
    inner: InitiatorContext,
    per_message: OnceCell<PerMessage>,
}

impl Context for Initiating {
    fn mechanism(&self) -> &'static str {
        "krb5"
    }

    fn mech_oid(&self) -> &[u8] {
        KRB5
    }

    fn step(&mut self, token: &[u8]) -> Result<Option<Vec<u8>>, GssError> {
        // The AP-REP: consuming it is the whole round, and there is nothing to send back until a
        // mechanism with another round exists.
        self.inner.step(token)?;
        Ok(None)
    }

    fn is_established(&self) -> bool {
        self.inner.is_established()
    }

    fn flags(&self) -> u32 {
        self.inner.flags()
    }

    fn client(&self) -> Option<&str> {
        // The initiator knows the name it asked to be; it arrives with the credentials, which this
        // context does not keep (it holds keys). `gss_inquire_context` on MIT reports it because its
        // context holds the name — a fact worth not inventing here.
        None
    }

    fn service(&self) -> Option<&str> {
        None
    }

    fn per_message(&self) -> Result<&PerMessage, GssError> {
        if !self.is_established() {
            return Err(GssError::NotEstablished);
        }
        // Built once: a fresh `PerMessage` per call would restart the send counter at the context's
        // initial sequence number, and two callers would emit tokens with the same SND_SEQ.
        if let Some(tokens) = self.per_message.get() {
            return Ok(tokens);
        }
        let tokens = self.inner.per_message_tokens()?;
        Ok(self
            .per_message
            .get_or_init(|| PerMessage::new(tokens, self.inner.send_seq())))
    }
}

/// The acceptor side of a Kerberos context, as the layer sees it.
#[derive(Debug)]
struct Accepting {
    inner: KerberosContext,
    /// Built at accept time: the acceptor is established the moment the AP-REQ verifies.
    per_message: Option<PerMessage>,
}

impl Context for Accepting {
    fn mechanism(&self) -> &'static str {
        "krb5"
    }

    fn mech_oid(&self) -> &[u8] {
        KRB5
    }

    fn step(&mut self, _token: &[u8]) -> Result<Option<Vec<u8>>, GssError> {
        // Checked, not ignored: an acceptor that swallowed a second token would report success for a
        // peer whose protocol exchange it did not understand.
        Err(GssError::UnexpectedToken)
    }

    fn is_established(&self) -> bool {
        self.inner.established
    }

    fn flags(&self) -> u32 {
        self.inner.gss_flags
    }

    fn client(&self) -> Option<&str> {
        Some(&self.inner.client_principal)
    }

    fn service(&self) -> Option<&str> {
        Some(&self.inner.service_principal)
    }

    fn per_message(&self) -> Result<&PerMessage, GssError> {
        self.per_message.as_ref().ok_or(GssError::NotEstablished)
    }
}

#[cfg(test)]
mod tests;
