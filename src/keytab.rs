//! Keytab sources: `FILE:`, `MEMORY:`, `ANY:` — and the names this crate refuses.
//!
//! Heimdal resolves a keytab name into an implementation (`krb5_kt_resolve`): `FILE:` for the MIT
//! file format, `MEMORY:` for a store shared by the parts of one process, `ANY:` for a comma
//! separated list searched in order, `AKF:`/`KFIL:` for an AFS keyfile, `KDB:` for a database. The
//! acceptor here took a [`Keytab`] and nothing else, so a daemon that learns its keys at runtime —
//! the ordinary shape for a service whose keytab is fetched at start-up, or a test double — had to
//! write a file to disk to be believed.
//!
//! # What is implemented
//!
//! * `FILE:<path>` — the MIT format, byte for byte what [`Keytab::load`] and [`Keytab::save`] read
//!   and write. A name with no recognised prefix is a `FILE:` name, as in MIT: `krb5_kt_resolve`
//!   looks for a registered type prefix and treats what is left as a file.
//! * `MEMORY:<name>` — a store inside the process, shared by every handle opened under that name.
//!   Heimdal refcounts it and drops it when the last handle closes (`keytab_memory.c`); here the
//!   registry holds a weak reference, so the entries go away with the last [`MemoryKeytab`], which
//!   is the same lifetime without a reference counter to get wrong.
//! * `ANY:<list>` — the names, comma separated, searched in the order written. The first source
//!   that holds a key answers, and a source that cannot be opened is a refusal rather than a silent
//!   skip: a chain that quietly loses its first element is a chain that authenticates with the
//!   second, and nobody finds out until the first is fixed.
//!
//! # What is not, and why
//!
//! * `KFIL:` / `AKF:` — the AFS keyfile format (Heimdal's `keytab_keyfile.c`, a directory of keys
//!   with a cell and a realm in it). Nothing in this crate speaks AFS: the acceptor is used by LDAP,
//!   SMB and NFS-over-GSSAPI, and none of them reads an AFS keyfile. Refused by name rather than
//!   implemented for a consumer that does not exist — the same rule this project applies to the SMB
//!   constructs it keeps out of `rrl-crypto`.
//! * `KDB:` — Heimdal's on-disk database keytab, which lives inside its own HDB. There is no such
//!   database on this side of the wire.
//! * `API:` — Heimdal's `ssapi` mapping, a plugin surface. A library that embeds into another
//!   program provides its own trait object instead, which is what [`KeytabSource`] is for.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

use crate::acceptor::{EncType, KerberosError, Keytab, Result, ServiceKey};

/// A store of service keys, addressable by name.
///
/// The one operation the acceptor needs is [`Self::find`], and it is a lookup rather than a scan on
/// purpose: a keytab carries one entry per enctype for the same principal, so a search by name alone
/// returns an arbitrary enctype and the ticket then fails its integrity check with an HMAC mismatch
/// that reads exactly like a wrong password.
pub trait KeytabSource: Send + Sync {
    /// The name this source was opened as, prefix included (`FILE:/etc/krb5.keytab`).
    fn name(&self) -> String;

    /// Every key the source holds, in its own order. A snapshot: a `MEMORY:` source may change
    /// between two calls, which is the point of it.
    fn keys(&self) -> Vec<ServiceKey>;

    /// The key for `principal` of enctype `enctype`, preferring version `kvno` when it is given and
    /// a match exists.
    ///
    /// `principal` is the service name without a realm (`host/server.example.com`) or with one
    /// (`host/server.example.com@EXAMPLE.COM`); both spellings are what callers already pass, and
    /// the realm is not part of the match because a keytab entry's realm is a property of the file,
    /// not of the ticket.
    ///
    /// A `kvno` that no entry carries is not a miss: a keytab mid-rotation legitimately holds the
    /// older version, and the enctype plus the HMAC decide correctness.
    fn find(&self, principal: &str, enctype: EncType, kvno: Option<u32>) -> Option<ServiceKey>;

    /// Whether [`Self::insert`] can store a key.
    fn is_writable(&self) -> bool {
        false
    }

    /// Stores `key`. A read-only source refuses rather than pretending.
    ///
    /// Named `insert` and not `add` on purpose: [`Keytab::add`] takes `&mut self`, and a trait
    /// method called `add` taking `&self` wins method resolution against it — the `&self` autoref is
    /// tried before `&mut self`, so `let mut kt = …; kt.add(key)` would call the trait's method,
    /// store nothing, and say nothing. That is not a hypothetical: it was the shape of this trait
    /// until a test found an empty keytab where it had just written a key.
    fn insert(&self, _key: ServiceKey) -> Result<()> {
        Err(KerberosError::KeytabLoad(format!(
            "{} is read-only: this source holds no writable store",
            self.name()
        )))
    }
}

/// The last fallback for a source that has no writable store and no better text to offer.
impl std::fmt::Debug for dyn KeytabSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeytabSource({})", self.name())
    }
}

/// Whether `key` is the entry for `principal`.
///
/// Two spellings are accepted because both are already in callers' hands: the service name alone and
/// the name with its realm. The comparison is on octets, not on a parsed
/// [`Principal`](rrl_krb_common::name::Principal), because a keytab entry's principal is a string
/// this crate never re-encodes.
fn matches(key: &ServiceKey, principal: &str) -> bool {
    key.principal == principal || format!("{}@{}", key.principal, key.realm) == principal
}

/// The entry [`KeytabSource::find`] returns out of `keys`.
///
/// Shared by every implementation: the order of preference is one decision, not one per source.
pub(crate) fn select(
    keys: &[ServiceKey],
    principal: &str,
    enctype: EncType,
    kvno: Option<u32>,
) -> Option<ServiceKey> {
    let candidates: Vec<&ServiceKey> = keys
        .iter()
        .filter(|k| matches(k, principal) && k.enctype == enctype)
        .collect();
    if let Some(kvno) = kvno
        && let Some(exact) = candidates.iter().find(|k| k.kvno == kvno)
    {
        return Some((*exact).clone());
    }
    candidates.first().map(|k| (*k).clone())
}

impl KeytabSource for Keytab {
    fn name(&self) -> String {
        // A keytab parsed from a file remembers no path: `load` drops it, and inventing one here
        // would be a lie in a log line. The callers who need a name open a source by name.
        "FILE:<unnamed>".to_owned()
    }

    fn keys(&self) -> Vec<ServiceKey> {
        // Named through the type, not through `self`: the trait method has the same name, and the
        // explicit path says which one is meant instead of relying on resolution order.
        Keytab::keys(self).to_vec()
    }

    fn find(&self, principal: &str, enctype: EncType, kvno: Option<u32>) -> Option<ServiceKey> {
        self.find_key_for(principal, enctype, kvno).cloned()
    }

    /// Read-only through this trait: `Keytab::add` needs `&mut self`, and a source shared behind a
    /// `Box<dyn KeytabSource>` cannot offer that. A daemon that must add keys opens the file as a
    /// source and writes it with [`Keytab::append_to`].
    fn is_writable(&self) -> bool {
        false
    }
}

/// The entries of one `MEMORY:` keytab, shared by every handle opened under its name.
type MemoryStore = Arc<RwLock<Vec<ServiceKey>>>;

/// Name to the store filed under it, as a weak reference: the entries live exactly as long as a
/// handle does.
type MemoryRegistry = Mutex<HashMap<String, Weak<RwLock<Vec<ServiceKey>>>>>;

/// The process-wide registry: a name and a weak reference, so the entries live exactly as long as
/// somebody holds a handle — Heimdal's refcount, without the count.
fn registry() -> &'static MemoryRegistry {
    static REGISTRY: OnceLock<MemoryRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A keytab that lives in the process, under a name every part of the program can look up.
///
/// Heimdal's `MEMORY:` (`lib/krb5/keytab_memory.c`): one store per name, created by the first
/// handle and dropped by the last. The name is not a file path and never touches the disk; a daemon
/// that receives its keys over a socket, or a test that wants a keytab without a temporary file,
/// is what it is for.
#[derive(Clone)]
pub struct MemoryKeytab {
    name: String,
    store: MemoryStore,
}

impl MemoryKeytab {
    /// The store called `name` (the part after `MEMORY:`), created empty if it does not exist yet.
    ///
    /// Two handles of the same name see each other's entries: that is the whole point, and it is
    /// what a test asserts rather than assumes.
    pub fn open(name: &str) -> Self {
        let mut registry = registry().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(store) = registry.get(name).and_then(Weak::upgrade) {
            return Self {
                name: name.to_owned(),
                store,
            };
        }
        let store: MemoryStore = Arc::new(RwLock::new(Vec::new()));
        registry.insert(name.to_owned(), Arc::downgrade(&store));
        Self {
            name: name.to_owned(),
            store,
        }
    }

    /// The keys currently stored, as a snapshot.
    pub fn entries(&self) -> Vec<ServiceKey> {
        self.store.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Replaces every entry. A daemon that receives a fresh keytab wholesale uses this rather than
    /// writing the keys one at a time into the source: an entry that is gone from the new list must
    /// be gone from the store, and adding without removing leaves the old kvno trusted.
    pub fn replace(&self, keys: Vec<ServiceKey>) {
        *self.store.write().unwrap_or_else(|e| e.into_inner()) = keys;
    }

    /// Removes the entry for `principal` of `enctype`, returning whether one was there.
    pub fn remove(&self, principal: &str, enctype: EncType, kvno: Option<u32>) -> bool {
        let mut keys = self.store.write().unwrap_or_else(|e| e.into_inner());
        let before = keys.len();
        keys.retain(|k| {
            !(matches(k, principal) && k.enctype == enctype && kvno.is_none_or(|v| v == k.kvno))
        });
        keys.len() != before
    }
}

impl KeytabSource for MemoryKeytab {
    fn name(&self) -> String {
        format!("MEMORY:{}", self.name)
    }

    fn keys(&self) -> Vec<ServiceKey> {
        self.entries()
    }

    fn find(&self, principal: &str, enctype: EncType, kvno: Option<u32>) -> Option<ServiceKey> {
        let keys = self.store.read().unwrap_or_else(|e| e.into_inner());
        select(&keys, principal, enctype, kvno)
    }

    fn is_writable(&self) -> bool {
        true
    }

    fn insert(&self, key: ServiceKey) -> Result<()> {
        self.store
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .push(key);
        Ok(())
    }
}

impl std::fmt::Debug for MemoryKeytab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryKeytab")
            .field("name", &self.name)
            .field("entries", &self.entries().len())
            .finish()
    }
}

/// Several sources, searched in the order they were written: Heimdal's `ANY:`.
///
/// The first source that holds a key answers, including when it holds one of the wrong enctype and a
/// later source holds the right one: a keytab that says "this principal has AES-256" is a statement
/// about the principal, and falling through to a weaker enctype elsewhere would be the KDC's
/// decision to make, not this chain's.
pub struct KeytabChain {
    name: String,
    sources: Vec<Box<dyn KeytabSource>>,
}

impl KeytabChain {
    /// A chain over `sources`, named `name` for logs and for [`KeytabSource::name`].
    pub fn new(name: impl Into<String>, sources: Vec<Box<dyn KeytabSource>>) -> Self {
        Self {
            name: name.into(),
            sources,
        }
    }

    /// The sources, in search order.
    pub fn sources(&self) -> &[Box<dyn KeytabSource>] {
        &self.sources
    }
}

impl KeytabSource for KeytabChain {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn keys(&self) -> Vec<ServiceKey> {
        let mut out = Vec::new();
        for source in &self.sources {
            for key in source.keys() {
                if !out.iter().any(|k: &ServiceKey| {
                    k.principal == key.principal
                        && k.realm == key.realm
                        && k.enctype == key.enctype
                        && k.kvno == key.kvno
                }) {
                    out.push(key);
                }
            }
        }
        out
    }

    fn find(&self, principal: &str, enctype: EncType, kvno: Option<u32>) -> Option<ServiceKey> {
        for source in &self.sources {
            if let Some(key) = source.find(principal, enctype, kvno) {
                return Some(key);
            }
        }
        None
    }

    fn is_writable(&self) -> bool {
        self.sources.iter().any(|s| s.is_writable())
    }

    /// Inserts into every writable source, as Heimdal's `any_add_entry` does: a key that is only in the
    /// first keytab of an `ANY:` list is a key that disappears from the search the moment that file
    /// is rotated.
    fn insert(&self, key: ServiceKey) -> Result<()> {
        let mut written = false;
        for source in &self.sources {
            if !source.is_writable() {
                continue;
            }
            source.insert(key.clone())?;
            written = true;
        }
        if !written {
            return Err(KerberosError::KeytabLoad(format!(
                "{} has no writable source, so this key was stored nowhere",
                self.name
            )));
        }
        Ok(())
    }
}

impl std::fmt::Debug for KeytabChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<String> = self.sources.iter().map(|s| s.name()).collect();
        f.debug_struct("KeytabChain")
            .field("name", &self.name)
            .field("sources", &names)
            .finish()
    }
}

/// The source `name` resolves to.
///
/// * `MEMORY:<name>` — a [`MemoryKeytab`], created if it does not exist.
/// * `ANY:<list>` — a [`KeytabChain`] over the comma separated names, each resolved the same way.
/// * `FILE:<path>`, or a name with no recognised prefix — a [`Keytab`] read from that path.
/// * `KFIL:`, `AKF:`, `KDB:`, `API:` — a refusal naming the format and why this crate does not read
///   it, rather than a "no such keytab" that sends the reader looking for the file.
pub fn resolve(name: &str) -> Result<Box<dyn KeytabSource>> {
    if let Some(rest) = strip_prefix(name, "MEMORY:") {
        if rest.is_empty() {
            return Err(KerberosError::KeytabLoad(
                "MEMORY: needs a name after the colon: the store is looked up by it".into(),
            ));
        }
        return Ok(Box::new(MemoryKeytab::open(rest)));
    }
    if let Some(rest) = strip_prefix(name, "ANY:") {
        return resolve_chain(rest).map(|c| Box::new(c) as Box<dyn KeytabSource>);
    }
    if let Some(rest) = strip_prefix(name, "FILE:") {
        if rest.is_empty() {
            return Err(KerberosError::KeytabLoad(
                "FILE: needs a path after the colon".into(),
            ));
        }
        return Ok(Box::new(Keytab::load(rest)?));
    }
    for (prefix, what) in [
        (
            "KFIL:",
            "the AFS keyfile format (Heimdal's keytab_keyfile.c); nothing in this crate speaks AFS",
        ),
        (
            "AKF:",
            "the AFS keyfile format (Heimdal's keytab_keyfile.c); nothing in this crate speaks AFS",
        ),
        (
            "KDB:",
            "Heimdal's on-disk database keytab, which lives inside its HDB and has no counterpart here",
        ),
        (
            "API:",
            "Heimdal's ssapi mapping, a plugin surface; an embedding program passes its own \
             KeytabSource instead",
        ),
    ] {
        if strip_prefix(name, prefix).is_some() {
            return Err(KerberosError::KeytabLoad(format!(
                "{prefix} is not implemented: {what}"
            )));
        }
    }
    // No recognised prefix: a file path, as MIT's `krb5_kt_resolve` treats one.
    Ok(Box::new(Keytab::load(name)?))
}

fn resolve_chain(list: &str) -> Result<KeytabChain> {
    if list.trim().is_empty() {
        return Err(KerberosError::KeytabLoad(
            "ANY: names no keytab; write ANY:FILE:/etc/krb5.keytab,FILE:/etc/krb5.keytab2".into(),
        ));
    }
    // The elements are checked as a whole before any is opened: a chain whose last element is
    // empty must say so, not report that the *first* file is missing — the operator reading that
    // would fix the wrong thing.
    let elements: Vec<&str> = list.split(',').map(str::trim).collect();
    if let Some(bad) = elements.iter().position(|e| e.is_empty()) {
        return Err(KerberosError::KeytabLoad(format!(
            "ANY:{list} has an empty element at position {}: a trailing or doubled comma would \
             make the chain shorter than it looks",
            bad + 1
        )));
    }
    let mut sources: Vec<Box<dyn KeytabSource>> = Vec::new();
    for element in elements {
        sources.push(resolve(element)?);
    }
    Ok(KeytabChain::new(format!("ANY:{list}"), sources))
}

/// `s.strip_prefix(prefix)`, case-insensitively.
///
/// Keytab type names are upper case in every implementation, and a configuration file that writes
/// `file:/etc/krb5.keytab` means the same thing: matching case-sensitively would turn it into a file
/// called `file:/etc/krb5.keytab`, which does not exist, and the error would name a path nobody
/// wrote.
fn strip_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

impl Keytab {
    /// Opens the keytab `name` names, whatever kind it is, and reads all of its keys into a
    /// [`Keytab`].
    ///
    /// This is the entry point for every caller that has a `&Keytab` API — which is the acceptor and
    /// the client — so the source types stay a way to *find* keys rather than a second set of types
    /// those functions would have to be generic over. A `MEMORY:` or `ANY:` name therefore yields a
    /// snapshot: a daemon that updates its keys must re-open, or hold the source from
    /// [`Keytab::resolve`] and use the acceptor's source entry points, which read the live store.
    pub fn open(name: &str) -> Result<Self> {
        Ok(Keytab::from_keys(resolve(name)?.keys()))
    }

    /// The source `name` names, live: a `MEMORY:` handle keeps seeing what others write, and an
    /// `ANY:` chain keeps searching every element on each lookup.
    pub fn resolve(name: &str) -> Result<Box<dyn KeytabSource>> {
        resolve(name)
    }
}

#[cfg(test)]
mod tests;
