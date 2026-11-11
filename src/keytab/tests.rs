//! The source table: what each name resolves to, and the one property each case turns on.
//!
//! The file cases use a real file in a temporary directory, because the format is the thing under
//! test and a fake reader would only restate the writer.

use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

fn key(principal: &str, realm: &str, enctype: EncType, kvno: u32, byte: u8) -> ServiceKey {
    ServiceKey::new(principal, realm, kvno, enctype, vec![byte; 32])
}

/// A directory that removes itself, unique per test so the tests run in parallel.
struct Dir {
    path: PathBuf,
}

impl Dir {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "rrl-krb5-keytab-{}-{}-{tag}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ------------------------------------------------------------------- FILE:

#[test]
fn the_file_prefix_reads_the_mit_format_back() {
    let dir = Dir::new("file");
    let path = dir.file("service.keytab");
    let mut written = Keytab::new();
    written.add(key(
        "host/s.example.com",
        "EXAMPLE.COM",
        EncType::AES256CtsHmacSha196,
        3,
        0x11,
    ));
    written.add(key(
        "host/s.example.com",
        "EXAMPLE.COM",
        EncType::AES128CtsHmacSha196,
        3,
        0x22,
    ));
    written.save(&path).unwrap();

    let opened = Keytab::open(&format!("FILE:{}", path.display())).unwrap();
    assert_eq!(opened.keys().len(), 2);
    let k = opened
        .find_key_for("host/s.example.com", EncType::AES256CtsHmacSha196, Some(3))
        .expect("the AES-256 entry");
    assert_eq!(k.key, vec![0x11; 32]);
}

#[test]
fn a_name_with_no_prefix_is_a_file_path() {
    // MIT's `krb5_kt_resolve` treats a name it does not recognise as a file, and a configuration
    // that has always written `default_keytab_name = /etc/krb5.keytab` must keep working.
    let dir = Dir::new("bare");
    let path = dir.file("bare.keytab");
    let mut written = Keytab::new();
    written.add(key(
        "nfs/h",
        "EXAMPLE.COM",
        EncType::AES256CtsHmacSha196,
        1,
        0x33,
    ));
    written.save(&path).unwrap();

    let opened = Keytab::open(&path.display().to_string()).unwrap();
    assert_eq!(opened.keys()[0].principal, "nfs/h");
}

#[test]
fn the_file_format_is_byte_for_byte_what_it_was() {
    // The property that matters for every other implementation: reading a keytab and writing it
    // again must not change one octet. A parser that reorders or re-encodes is a keytab `klist`
    // stops reading, and no test of the keys themselves would notice.
    let dir = Dir::new("bytes");
    let path = dir.file("round.keytab");
    let mut written = Keytab::new();
    written.add(key(
        "host/a",
        "EXAMPLE.COM",
        EncType::AES256CtsHmacSha196,
        7,
        0x44,
    ));
    written.add(key(
        "host/a",
        "EXAMPLE.COM",
        EncType::AES128CtsHmacSha196,
        7,
        0x55,
    ));
    written.add(key(
        "cifs/b.example.com",
        "EXAMPLE.COM",
        EncType::AES256CtsHmacSha196,
        1,
        0x66,
    ));
    written.save(&path).unwrap();
    let original = std::fs::read(&path).unwrap();

    let reopened = Keytab::open(&format!("FILE:{}", path.display())).unwrap();
    assert_eq!(
        reopened.to_bytes(),
        original,
        "a round trip through the parser must reproduce the file exactly"
    );
    assert_eq!(&original[..2], &[0x05, 0x02], "version 0x0502");
}

#[test]
fn the_prefix_is_matched_without_regard_to_case() {
    let dir = Dir::new("case");
    let path = dir.file("case.keytab");
    let mut written = Keytab::new();
    written.add(key(
        "host/c",
        "EXAMPLE.COM",
        EncType::AES256CtsHmacSha196,
        1,
        0x77,
    ));
    written.save(&path).unwrap();

    // Lower case: without this, `file:/…` would be taken for a file whose *name* contains a colon,
    // and the error would name a path nobody wrote.
    let opened = Keytab::open(&format!("file:{}", path.display())).unwrap();
    assert_eq!(opened.keys().len(), 1);
}

#[test]
fn a_file_that_is_not_there_is_an_error_naming_the_path() {
    let err = resolve("/nonexistent/krb5.keytab").unwrap_err().to_string();
    assert!(
        err.contains("/nonexistent/krb5.keytab"),
        "the error must name the file: {err}"
    );
}

// ----------------------------------------------------------------- MEMORY:

#[test]
fn two_memory_handles_of_one_name_see_each_others_keys() {
    // The whole point of the source: a daemon learns its keys in one place and accepts tickets in
    // another, without the two passing a `Keytab` through ten layers.
    let writer = MemoryKeytab::open("shared-in-test-1");
    let reader = Keytab::resolve("MEMORY:shared-in-test-1").unwrap();
    writer
        .insert(key(
            "host/m",
            "EXAMPLE.COM",
            EncType::AES256CtsHmacSha196,
            1,
            0x88,
        ))
        .unwrap();

    let found = reader
        .find("host/m", EncType::AES256CtsHmacSha196, None)
        .expect("the key written through the other handle");
    assert_eq!(found.key, vec![0x88; 32]);
}

#[test]
fn a_memory_store_goes_away_with_its_last_handle() {
    // Heimdal refcounts the store and frees it on the last close; the registry here holds a weak
    // reference, so the entries go with the last handle. A store that outlived its handles would
    // keep a rotated key trusted for the lifetime of the process.
    {
        let handle = MemoryKeytab::open("ephemeral-in-test");
        handle
            .insert(key(
                "host/e",
                "EXAMPLE.COM",
                EncType::AES256CtsHmacSha196,
                1,
                0x99,
            ))
            .unwrap();
        assert_eq!(handle.entries().len(), 1);
    }
    let fresh = MemoryKeytab::open("ephemeral-in-test");
    assert!(
        fresh.entries().is_empty(),
        "a store nobody holds must not survive"
    );
}

#[test]
fn replace_drops_the_entries_the_new_list_does_not_have() {
    // A rotation that adds the new key and forgets to drop the old one leaves the old kvno trusted,
    // which is the same as not rotating.
    let store = MemoryKeytab::open("replace-in-test");
    store
        .insert(key(
            "host/r",
            "EXAMPLE.COM",
            EncType::AES256CtsHmacSha196,
            1,
            0x01,
        ))
        .unwrap();
    store.replace(vec![key(
        "host/r",
        "EXAMPLE.COM",
        EncType::AES256CtsHmacSha196,
        2,
        0x02,
    )]);
    assert!(
        store.entries().iter().all(|k| k.kvno == 2),
        "the old kvno must be gone: {:#?}",
        store.entries()
    );
    let latest = store
        .find("host/r", EncType::AES256CtsHmacSha196, None)
        .expect("the new key");
    assert_eq!(latest.kvno, 2);
}

#[test]
fn remove_takes_one_entry_and_says_whether_it_was_there() {
    let store = MemoryKeytab::open("remove-in-test");
    store
        .insert(key(
            "host/x",
            "EXAMPLE.COM",
            EncType::AES256CtsHmacSha196,
            1,
            0x03,
        ))
        .unwrap();
    store
        .insert(key(
            "host/x",
            "EXAMPLE.COM",
            EncType::AES128CtsHmacSha196,
            1,
            0x04,
        ))
        .unwrap();
    assert!(store.remove("host/x", EncType::AES128CtsHmacSha196, None));
    assert!(!store.remove("host/x", EncType::AES128CtsHmacSha196, None));
    assert_eq!(store.entries().len(), 1, "the other enctype stays");
}

#[test]
fn a_memory_name_must_not_be_empty() {
    let err = Keytab::open("MEMORY:").unwrap_err().to_string();
    assert!(err.contains("needs a name"), "{err}");
}

// -------------------------------------------------------------------- ANY:

#[test]
fn any_searches_its_sources_in_the_order_written() {
    let dir = Dir::new("any-order");
    let first = dir.file("first.keytab");
    let second = dir.file("second.keytab");

    let mut only_second = Keytab::new();
    only_second.add(key(
        "host/s",
        "EXAMPLE.COM",
        EncType::AES256CtsHmacSha196,
        1,
        0xAA,
    ));
    only_second.save(&second).unwrap();
    Keytab::new().save(&first).unwrap();

    let chain = Keytab::resolve(&format!(
        "ANY:FILE:{},FILE:{}",
        first.display(),
        second.display()
    ))
    .unwrap();
    assert!(
        chain
            .find("host/s", EncType::AES256CtsHmacSha196, None)
            .is_some(),
        "the second source holds it, and the chain must reach it"
    );
    assert_eq!(
        chain.name(),
        format!("ANY:FILE:{},FILE:{}", first.display(), second.display())
    );
}

#[test]
fn the_first_source_to_hold_a_key_answers() {
    // Both files carry a key for the same principal and enctype, with different material. The chain
    // must not merge them or pick the later one: the order written is the order of precedence, which
    // is how an operator says "the current keytab wins".
    let dir = Dir::new("any-first");
    let first = dir.file("a.keytab");
    let second = dir.file("b.keytab");
    let mut a = Keytab::new();
    a.add(key(
        "host/p",
        "EXAMPLE.COM",
        EncType::AES256CtsHmacSha196,
        1,
        0x0A,
    ));
    a.save(&first).unwrap();
    let mut b = Keytab::new();
    b.add(key(
        "host/p",
        "EXAMPLE.COM",
        EncType::AES256CtsHmacSha196,
        1,
        0x0B,
    ));
    b.save(&second).unwrap();

    let chain = Keytab::resolve(&format!(
        "ANY:FILE:{},FILE:{}",
        first.display(),
        second.display()
    ))
    .unwrap();
    let found = chain
        .find("host/p", EncType::AES256CtsHmacSha196, None)
        .unwrap();
    assert_eq!(found.key, vec![0x0A; 32], "the first source wins");
}

#[test]
fn a_key_nobody_holds_is_not_found_anywhere() {
    let dir = Dir::new("any-none");
    let path = dir.file("empty.keytab");
    Keytab::new().save(&path).unwrap();
    let chain = Keytab::resolve(&format!("ANY:FILE:{}", path.display())).unwrap();
    assert!(
        chain
            .find("host/q", EncType::AES256CtsHmacSha196, None)
            .is_none()
    );
    assert!(chain.keys().is_empty());
}

#[test]
fn any_merges_the_key_list_without_duplicates() {
    let dir = Dir::new("any-merge");
    let first = dir.file("m1.keytab");
    let second = dir.file("m2.keytab");
    let mut a = Keytab::new();
    a.add(key(
        "host/m",
        "EXAMPLE.COM",
        EncType::AES256CtsHmacSha196,
        1,
        0x0C,
    ));
    a.save(&first).unwrap();
    let mut b = Keytab::new();
    b.add(key(
        "host/m",
        "EXAMPLE.COM",
        EncType::AES256CtsHmacSha196,
        1,
        0x0C,
    ));
    b.add(key(
        "host/n",
        "EXAMPLE.COM",
        EncType::AES256CtsHmacSha196,
        1,
        0x0D,
    ));
    b.save(&second).unwrap();

    let chain = Keytab::resolve(&format!(
        "ANY:FILE:{},FILE:{}",
        first.display(),
        second.display()
    ))
    .unwrap();
    let keys = chain.keys();
    assert_eq!(keys.len(), 2, "the same entry twice counts once: {keys:?}");
}

#[test]
fn any_refuses_an_empty_element_rather_than_being_shorter_than_it_looks() {
    let err = Keytab::resolve("ANY:FILE:/etc/krb5.keytab,")
        .unwrap_err()
        .to_string();
    assert!(err.contains("empty element"), "{err}");
    let err = Keytab::resolve("ANY:").unwrap_err().to_string();
    assert!(err.contains("names no keytab"), "{err}");
}

#[test]
fn a_chain_that_names_a_missing_file_is_refused_at_resolve_time() {
    // A chain that silently drops the source it could not open authenticates with the next one, and
    // nobody finds out until the missing file is fixed and the keys turn out to differ.
    let dir = Dir::new("any-missing");
    let present = dir.file("present.keytab");
    Keytab::new().save(&present).unwrap();
    let err = Keytab::resolve(&format!(
        "ANY:FILE:{},FILE:{}",
        dir.file("absent.keytab").display(),
        present.display()
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("absent.keytab"), "{err}");
}

// ----------------------------------------------------------- what is refused

#[test]
fn the_formats_this_crate_does_not_read_are_refused_by_name() {
    // Each of these exists in Heimdal, and each refusal says what the format is and why there is no
    // reader here — a "no such keytab" would send the reader looking for a file.
    for (name, needle) in [
        ("KFIL:/etc/krb5.akf", "AFS keyfile"),
        ("AKF:/etc/krb5.akf", "AFS keyfile"),
        ("KDB:/var/heimdal/kdb", "HDB"),
        ("API:http://example.com/keys", "ssapi"),
    ] {
        let err = Keytab::resolve(name).unwrap_err().to_string();
        assert!(
            err.contains(needle) && err.contains("not implemented"),
            "{name}: {err}"
        );
    }
}

#[test]
fn a_keytab_by_value_is_read_only_through_the_source_trait() {
    // `Keytab::add` needs `&mut self`, which a `Box<dyn KeytabSource>` cannot lend. Saying so is
    // better than a no-op that leaves the caller's key nowhere.
    let mut kt = Keytab::new();
    kt.add(key(
        "host/z",
        "EXAMPLE.COM",
        EncType::AES256CtsHmacSha196,
        1,
        0xEE,
    ));
    let source: &dyn KeytabSource = &kt;
    assert!(!source.is_writable());
    assert!(
        source
            .insert(key(
                "host/y",
                "EXAMPLE.COM",
                EncType::AES256CtsHmacSha196,
                1,
                0xEF
            ))
            .is_err()
    );
    assert_eq!(source.keys().len(), 1, "the refused insert stored nothing");
}

#[test]
fn a_read_only_source_refuses_an_add_through_a_chain() {
    // A chain of files has nothing writable, and the refusal must not be silent: `ANY:` over files
    // is read-only, and a caller that expects a store has to be told.
    let dir = Dir::new("chain-readonly");
    let path = dir.file("ro.keytab");
    Keytab::new().save(&path).unwrap();
    let chain = Keytab::resolve(&format!("ANY:FILE:{}", path.display())).unwrap();
    assert!(!chain.is_writable());
    let err = chain
        .insert(key(
            "host/w",
            "EXAMPLE.COM",
            EncType::AES256CtsHmacSha196,
            1,
            0xF0,
        ))
        .unwrap_err()
        .to_string();
    assert!(err.contains("stored nowhere"), "{err}");
}

#[test]
fn a_chain_holding_a_memory_store_is_writable_and_writes_there() {
    let dir = Dir::new("chain-memory");
    let path = dir.file("base.keytab");
    Keytab::new().save(&path).unwrap();
    let store = format!("chain-memory-{}", std::process::id());
    let chain = Keytab::resolve(&format!("ANY:MEMORY:{store},FILE:{}", path.display())).unwrap();
    assert!(chain.is_writable());
    chain
        .insert(key(
            "host/w",
            "EXAMPLE.COM",
            EncType::AES256CtsHmacSha196,
            1,
            0xF1,
        ))
        .unwrap();
    assert!(
        MemoryKeytab::open(&store)
            .find("host/w", EncType::AES256CtsHmacSha196, None)
            .is_some(),
        "the writable element of the chain received it"
    );
}

#[test]
fn the_kvno_the_ticket_names_wins_and_a_stale_one_falls_back() {
    // Two versions of one key is the ordinary state of a keytab mid-rotation. The ticket names the
    // version it was sealed with, so that entry is the one to try first; a ticket naming a version
    // nobody has must still be tried against what the file does hold, because a keytab that was not
    // re-read after `ktadd` carries the older kvno and the HMAC is the real judge.
    let store = MemoryKeytab::open("kvno-in-test");
    store
        .insert(key(
            "host/k",
            "EXAMPLE.COM",
            EncType::AES256CtsHmacSha196,
            1,
            0x10,
        ))
        .unwrap();
    store
        .insert(key(
            "host/k",
            "EXAMPLE.COM",
            EncType::AES256CtsHmacSha196,
            2,
            0x20,
        ))
        .unwrap();

    let asked_2 = store
        .find("host/k", EncType::AES256CtsHmacSha196, Some(2))
        .expect("kvno 2 is there");
    assert_eq!(asked_2.key, vec![0x20; 32], "the version the ticket names");

    let stale = store
        .find("host/k", EncType::AES256CtsHmacSha196, Some(9))
        .expect("a version nobody has falls back to what the store holds");
    assert_eq!(stale.kvno, 1, "the first entry, in store order");

    let unstated = store
        .find("host/k", EncType::AES256CtsHmacSha196, None)
        .expect("no kvno asked for");
    assert_eq!(unstated.kvno, 1);
}
