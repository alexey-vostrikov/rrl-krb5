//! `id-pkinit-san` (RFC 4556 §3.2.2): the `KRB5PrincipalName` inside a certificate's
//! `subjectAltName`, decoded into a [`Principal`].
//!
//! # Why this is here and not with the certificate
//!
//! A certificate is not a Kerberos structure, and `rrl_crypto::pkcs` reads one without knowing what
//! a realm is. This is the one thing about a certificate that does: the otherName names a
//! principal, so `Cert::kerberos_alt_names` hands out those payloads as DER and the decode lives
//! beside the type it produces.
//!
//! ```text
//! KRB5PrincipalName ::= SEQUENCE { realm [0] Realm, principalName [1] PrincipalName }
//! ```

use super::*;

/// The principals a certificate names in its PKINIT `subjectAltName`, and its dNSNames as text.
///
/// The names are what the KDC accepts the certificate for, unless the KDC maps certificates to
/// principals some other way (`pkinit_principal_in_certificate` off).
pub(crate) fn san(cert: &x509::Cert) -> der::Result<(Vec<Principal>, Vec<String>)> {
    let (payloads, dns) = cert.kerberos_alt_names()?;
    let mut principals = Vec::with_capacity(payloads.len());
    for payload in payloads {
        let f = der::Fields::parse("KRB5PrincipalName", &payload)?;
        let realm = f.get(0)?.string()?;
        principals.push(
            Principal::decode_name(f.get(1)?, realm).map_err(|e| der::DerError(e.to_string()))?,
        );
    }
    Ok((principals, dns))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture the crypto layer's own test reads, decoded all the way through: the payload
    /// arrives as DER and comes out as a principal.
    ///
    /// Worth its own test rather than trusting the two halves: `kerberos_alt_names` hands out the
    /// content of the `KRB5PrincipalName` SEQUENCE, and `Fields::parse` takes exactly that — a
    /// disagreement about whether the tag is included would compile and produce nonsense.
    #[test]
    fn a_kdc_certificate_names_krbtgt_of_its_realm() {
        let cert = x509::parse_certs(include_bytes!("testdata/kdc.pem")).unwrap();
        let (principals, dns) = san(&cert[0]).unwrap();
        assert_eq!(
            principals,
            [Principal::krbtgt("TEST.REALM")],
            "the certificate is the realm's own krbtgt"
        );
        assert!(dns.is_empty(), "and it names no DNS names");
    }

    /// A certificate whose SAN carries a dNSName and no PKINIT otherName: no principals, the name
    /// as text.
    #[test]
    fn a_host_certificate_names_no_principal() {
        let cert = x509::parse_certs(include_bytes!("testdata/host.pem")).unwrap();
        let (principals, dns) = san(&cert[0]).unwrap();
        assert!(principals.is_empty());
        assert_eq!(dns, ["kdc.test.realm"]);
    }
}
