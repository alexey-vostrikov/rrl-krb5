//! `HostAddress` (RFC 4120 §5.2.5): the addresses a ticket is good for.
//!
//! A ticket can be bound to the client's addresses, and a *forwarded* ticket is bound to the
//! addresses of the host it is forwarded **to** — that is the difference between "this credential
//! may be used from anywhere" and "this credential may be used from that machine". Heimdal's
//! `krb5_get_forwarded_creds` (`lib/krb5/get_for_creds.c`) resolves the target hostname when the
//! source TGT carries addresses, and leaves the forwarded ticket addressless when it does not; the
//! reason is spelled out there ("If the tickets that are forwarded are address-less, the forwarded
//! tickets will also be address-less") and it is a policy an operator can override with
//! `no-addresses` per realm.
//!
//! # What this module decides, and why
//!
//! The address *types* are the IANA ones RFC 4120 §7.5.10 registers: 20 for IPv4 and 24 for IPv6,
//! and those are the only two this crate emits, because they are the only two `std::net` can
//! produce. The octets are the plain network-order address, which is what every KDC and acceptor
//! compares against.
//!
//! Resolution uses `std::net::ToSocketAddrs` rather than this crate's `dns` module: the client
//! already resolves KDC hostnames through the configuration and the platform, and an address for a
//! forwarded ticket is the same kind of lookup. `block_dns` — MIT's switch that forbids name
//! resolution in a security-sensitive path — is honoured for the same reason Heimdal honours it:
//! with it set, only numeric addresses are accepted, and a hostname is a refusal rather than a
//! lookup.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use crate::client::{ClientError, Result};
use crate::der;
use crate::der::Fields;

/// IANA address type for IPv4 (RFC 4120 §7.5.10).
pub const ADDRTYPE_INET: i32 = 20;
/// IANA address type for IPv6.
pub const ADDRTYPE_INET6: i32 = 24;

/// One `HostAddress`:
///
/// ```text
/// HostAddress ::= SEQUENCE { addr-type [0] Int32, address [1] OCTET STRING }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HostAddress {
    /// The IANA address type: 20 for IPv4, 24 for IPv6.
    pub addr_type: i32,
    /// The address, in network order.
    pub address: Vec<u8>,
}

impl HostAddress {
    /// An address of `addr_type` whose octets are `address`.
    ///
    /// Not validated against the length the type implies: a KDC reads what it is sent, and a client
    /// that invents a length here would be describing an address no acceptor can match. What this
    /// crate *produces* is always 4 or 16 octets, because it comes from [`HostAddress::of`].
    pub fn new(addr_type: i32, address: impl Into<Vec<u8>>) -> Self {
        Self {
            addr_type,
            address: address.into(),
        }
    }

    /// The address of a `SocketAddr`, with its port dropped: a ticket names where, not which
    /// service.
    pub fn of(addr: SocketAddr) -> Self {
        match addr.ip() {
            IpAddr::V4(v4) => Self::new(ADDRTYPE_INET, v4.octets().to_vec()),
            IpAddr::V6(v6) => Self::new(ADDRTYPE_INET6, v6.octets().to_vec()),
        }
    }

    /// The address as a std value, when the type is one this crate knows.
    pub fn socket_ip(&self) -> Option<IpAddr> {
        match (self.addr_type, self.address.len()) {
            (ADDRTYPE_INET, 4) => {
                let mut o = [0u8; 4];
                o.copy_from_slice(&self.address);
                Some(IpAddr::from(o))
            }
            (ADDRTYPE_INET6, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&self.address);
                Some(IpAddr::from(o))
            }
            _ => None,
        }
    }

    /// The `HostAddress` as it appears inside `caddr`.
    pub fn encode(&self) -> Vec<u8> {
        der::seq(&[
            der::field(0, der::int(i64::from(self.addr_type))),
            der::field(1, der::octets(&self.address)),
        ])
    }

    /// Reads one `HostAddress` from the content of its `SEQUENCE`.
    ///
    /// Content, not the whole TLV: `Fields::parse` takes what is inside a sequence, which is the
    /// convention every decoder in this crate follows.
    pub fn decode(content: &[u8]) -> Result<Self> {
        let f = Fields::parse("HostAddress", content)?;
        Ok(Self {
            addr_type: f.int(0, "HostAddress.addr-type")? as i32,
            // `octets`, not `bytes`: the latter hands back the whole TLV, so the address
            // would carry its own tag and length in front and match nothing.
            address: f.octets(1, "HostAddress.address")?.to_vec(),
        })
    }
}

/// `caddr [8]`: a SEQUENCE OF HostAddress.
pub(crate) fn encode_caddr(addresses: &[HostAddress]) -> Vec<u8> {
    der::seq(
        &addresses
            .iter()
            .map(HostAddress::encode)
            .collect::<Vec<_>>(),
    )
}

/// The `HostAddress`es of a `caddr [8]` value, which is a whole `SEQUENCE OF HostAddress`.
pub fn decode_caddr(content: &[u8]) -> Result<Vec<HostAddress>> {
    der::seq_of("caddr", content, der::SEQUENCE)?
        .into_iter()
        .map(HostAddress::decode)
        .collect()
}

/// The addresses `host` resolves to, de-duplicated, without ports.
///
/// `numeric_only` is MIT's `block_dns`: with it set, a name that is not an address literal is a
/// refusal, because resolving one in this path is the kind of hidden network dependency that turns a
/// security decision into whatever DNS answered.
pub fn of_host(host: &str, numeric_only: bool) -> Result<Vec<HostAddress>> {
    let addrs: Vec<SocketAddr> = if numeric_only {
        match host.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, 0)],
            Err(_) => {
                return Err(ClientError::Protocol(format!(
                    "block_dns is set and {host} is not an address literal, so it cannot be \
                     bound into a forwarded ticket"
                )));
            }
        }
    } else {
        // Port 0: the ticket names an address, and the lookup only wants the IP.
        format!("{host}:0")
            .to_socket_addrs()
            .map_err(|e| {
                ClientError::Protocol(format!("resolving {host} for a forwarded ticket: {e}"))
            })?
            .collect()
    };
    let mut out: Vec<HostAddress> = Vec::new();
    for addr in addrs {
        let ha = HostAddress::of(addr);
        if !out.contains(&ha) {
            out.push(ha);
        }
    }
    if out.is_empty() {
        return Err(ClientError::Protocol(format!(
            "{host} resolved to no address, so a forwarded ticket cannot be bound to it"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
