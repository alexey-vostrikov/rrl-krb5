//! ASN.1 DER, in the `rrl-krb` crate.
//!
//! The implementation lives there because the KDC that produces the tickets this crate accepts
//! needs the same decoder. Two copies of a length encoder are two ways to disagree about the
//! octets a checksum covers, and that disagreement surfaces as a rejected ticket in the middle of
//! an exchange rather than as a failing test.
//!
//! Re-exported rather than wrapped so that `der::SEQUENCE`, `der::Reader` and `Fields` keep
//! resolving here, and so that a `DerError` raised on one side is the same type the other side
//! matches on.

pub use rrl_krb::der::*;
