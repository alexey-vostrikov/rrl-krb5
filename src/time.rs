//! `KerberosTime`, in the `rrl-krb-common` crate.
//!
//! Shared with the KDC: a ticket's `endtime` written by one and read by the other has to be the
//! same instant, and the calendar arithmetic that decides it is not something to keep in two
//! places.

pub use rrl_krb_common::time::*;
