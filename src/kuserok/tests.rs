//! The `kuserok` table: every case Heimdal distinguishes, and the one thing each case turns on.
//!
//! The files are real — a temporary home directory the test owns — because the checks under test
//! are the mode and the owner of a file, and a fake filesystem would only restate the code. The
//! *users* are fake, because a test cannot create a uid it does not have.
//!
//! Every case names what changes the answer. A fixture in which two different facts coincide —
//! "there is no k5login" and "SIMPLE matches", say — cannot tell the rules apart, and would go on
//! passing after the rule it was meant to pin had been deleted.

use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

const REALM: &str = "EXAMPLE.COM";

fn principal(s: &str) -> Principal {
    Principal::parse(s).unwrap()
}

/// A home directory that removes itself, unique per test so the tests can run in parallel.
struct Home {
    path: PathBuf,
}

impl Home {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "rrl-krb5-kuserok-{}-{}-{tag}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    /// Writes a file and pins its mode, because the umask would otherwise decide the mode and the
    /// mode is what the test is about.
    fn file(&self, name: &str, contents: &str, mode: u32) -> PathBuf {
        let path = self.path.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, contents).unwrap();
        set_mode(&path, mode);
        path
    }

    fn dir(&self, name: &str) -> PathBuf {
        let path = self.path.join(name);
        std::fs::create_dir_all(&path).unwrap();
        set_mode(&path, 0o755);
        path
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_mode(_path: &std::path::Path, _mode: u32) {}

/// The user database, as a test needs it: one account, whose uid is this process's.
struct Users {
    name: String,
    uid: u32,
    home: PathBuf,
}

impl Users {
    fn new(name: &str, home: &Home) -> Self {
        Self {
            name: name.to_owned(),
            uid: current_uid(),
            home: home.path.clone(),
        }
    }

    /// The same account, but with a uid no file can have: the "owned by somebody else" case.
    fn with_foreign_uid(mut self) -> Self {
        self.uid = 1_000_000_000 + current_uid();
        self
    }
}

impl LocalUsers for Users {
    fn home_dir(&self, luser: &str) -> Option<PathBuf> {
        (luser == self.name).then(|| self.home.clone())
    }

    fn uid(&self, luser: &str) -> Option<u32> {
        (luser == self.name).then_some(self.uid)
    }
}

#[cfg(unix)]
fn current_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(".").map(|m| m.uid()).unwrap_or(0)
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

fn conf(text: &str) -> Krb5Conf {
    Krb5Conf::parse(text).unwrap()
}

/// The policy of a host whose realm is `EXAMPLE.COM`, with no `kuserok` of its own.
fn default_policy() -> Kuserok {
    Kuserok::from_conf(&conf(&format!("[libdefaults]\n default_realm = {REALM}\n"))).unwrap()
}

fn authoritative_policy() -> Kuserok {
    Kuserok::from_conf(&conf(&format!(
        "[libdefaults]\n default_realm = {REALM}\n k5login_authoritative = true\n"
    )))
    .unwrap()
}

/// What a refusal says, for the assertions that are about the message.
fn denial_text(r: Result<Grant, Denial>) -> String {
    match r {
        Ok(g) => panic!("expected a refusal, got {} because {}", g.rule, g.reason),
        Err(d) => format!("{d}"),
    }
}

// ---------------------------------------------------------------- the default chain

#[test]
fn a_local_one_component_principal_is_allowed_by_simple_with_no_file_at_all() {
    let home = Home::new("simple");
    let users = Users::new("alice", &home);
    let grant = default_policy()
        .check(&users, &principal("alice@EXAMPLE.COM"), "alice")
        .expect("alice@EXAMPLE.COM is alice in a local realm");
    assert_eq!(grant.rule, "SIMPLE");
    assert!(grant.reason.contains("local realm"), "{}", grant.reason);
}

#[test]
fn a_principal_from_another_realm_is_not_simple() {
    let home = Home::new("foreign-realm");
    let users = Users::new("alice", &home);
    let why = denial_text(default_policy().check(&users, &principal("alice@OTHER.REALM"), "alice"));
    assert!(
        why.contains("not a realm this host counts as local"),
        "the refusal must say which realm was rejected and why: {why}"
    );
}

#[test]
fn a_service_principal_of_two_components_is_not_simple() {
    // `alice/admin@EXAMPLE.COM` is a different principal from `alice@EXAMPLE.COM`, and SIMPLE
    // matches one-component names only — Heimdal's `check_an2ln` comment says the same.
    let home = Home::new("two-components");
    let users = Users::new("alice", &home);
    let why =
        denial_text(default_policy().check(&users, &principal("alice/admin@EXAMPLE.COM"), "alice"));
    assert!(why.contains("2 components"), "{why}");
}

#[test]
fn a_name_that_differs_from_the_local_user_is_refused() {
    let home = Home::new("other-name");
    let users = Users::new("alice", &home);
    let why = denial_text(default_policy().check(&users, &principal("bob@EXAMPLE.COM"), "alice"));
    assert!(why.contains("is not named alice"), "{why}");
}

// ---------------------------------------------------------------- ~/.k5login

#[test]
fn a_principal_listed_in_k5login_is_allowed_by_that_file() {
    let home = Home::new("k5login-match");
    home.file(".k5login", "bob@OTHER.REALM\n", 0o644);
    let users = Users::new("alice", &home);
    let grant = default_policy()
        .check(&users, &principal("bob@OTHER.REALM"), "alice")
        .expect("the file names the principal");
    assert_eq!(grant.rule, "USER-K5LOGIN");
}

#[test]
fn a_line_without_a_realm_takes_the_default_realm() {
    // `krb5_parse_name` fills the realm in from `[libdefaults] default_realm`, so a file that says
    // `bob` is a file that says `bob@EXAMPLE.COM` — and not a line that fails to parse.
    let home = Home::new("k5login-bare");
    home.file(".k5login", "# the staff\n\nbob\n", 0o644);
    let users = Users::new("alice", &home);
    assert!(
        default_policy()
            .check(&users, &principal("bob@EXAMPLE.COM"), "alice")
            .is_ok(),
        "a bare name and a comment line must both be read as intended"
    );
}

#[test]
fn a_k5login_that_does_not_list_the_principal_falls_through_when_it_is_not_authoritative() {
    // The nuance that makes the option worth having: without `k5login_authoritative` the file is a
    // source of extra identities, not a whitelist. Heimdal runs SIMPLE afterwards for exactly this.
    let home = Home::new("k5login-fallthrough");
    home.file(".k5login", "bob@OTHER.REALM\n", 0o644);
    let users = Users::new("alice", &home);
    let grant = default_policy()
        .check(&users, &principal("alice@EXAMPLE.COM"), "alice")
        .expect("SIMPLE still applies");
    assert_eq!(grant.rule, "SIMPLE");
}

#[test]
fn an_authoritative_k5login_turns_the_same_case_into_a_refusal() {
    let home = Home::new("k5login-authoritative");
    home.file(".k5login", "bob@OTHER.REALM\n", 0o644);
    let users = Users::new("alice", &home);
    let why =
        denial_text(authoritative_policy().check(&users, &principal("alice@EXAMPLE.COM"), "alice"));
    assert!(why.contains("k5login_authoritative"), "{why}");
}

#[test]
fn a_group_writable_k5login_is_not_trusted() {
    // Anybody in the group could rewrite the file, so the file cannot grant anything — and with
    // `k5login_authoritative` it also refuses, because the user does have a k5login.
    let home = Home::new("k5login-mode");
    home.file(".k5login", "alice@EXAMPLE.COM\n", 0o664);
    let users = Users::new("alice", &home);
    let why =
        denial_text(authoritative_policy().check(&users, &principal("alice@EXAMPLE.COM"), "alice"));
    assert!(
        why.contains("writable by group or other") && why.contains("0664"),
        "the refusal must name the mode it found: {why}"
    );
    // Without authority the file is skipped, and SIMPLE decides — still a login, but not because of
    // the file.
    let grant = default_policy()
        .check(&users, &principal("alice@EXAMPLE.COM"), "alice")
        .expect("SIMPLE");
    assert_eq!(grant.rule, "SIMPLE");
}

#[test]
fn a_k5login_owned_by_somebody_else_is_not_trusted() {
    let home = Home::new("k5login-owner");
    home.file(".k5login", "bob@EXAMPLE.COM\n", 0o644);
    let users = Users::new("alice", &home).with_foreign_uid();
    let why =
        denial_text(authoritative_policy().check(&users, &principal("bob@EXAMPLE.COM"), "alice"));
    assert!(why.contains("must be owned by uid"), "{why}");
}

#[test]
fn a_directory_named_k5login_is_not_a_list_of_principals() {
    let home = Home::new("k5login-dir");
    home.dir(".k5login");
    let users = Users::new("alice", &home);
    let why =
        denial_text(authoritative_policy().check(&users, &principal("alice@EXAMPLE.COM"), "alice"));
    assert!(why.contains("is a directory"), "{why}");
}

#[cfg(unix)]
#[test]
fn a_symlinked_k5login_is_followed_and_the_target_is_what_counts() {
    // Heimdal opens the file and stats the descriptor, so a link is followed. The property that
    // matters is the mode of the file actually read: a link to a group-writable file grants nothing.
    let home = Home::new("k5login-symlink");
    let target = home.file("real-list", "alice@EXAMPLE.COM\n", 0o664);
    let link = home.path.join(".k5login");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let users = Users::new("alice", &home);
    let why =
        denial_text(authoritative_policy().check(&users, &principal("alice@EXAMPLE.COM"), "alice"));
    assert!(why.contains("writable by group or other"), "{why}");

    // And a link to a file that is properly protected works: the link itself is not the subject.
    set_mode(&target, 0o644);
    assert!(
        authoritative_policy()
            .check(&users, &principal("alice@EXAMPLE.COM"), "alice")
            .is_ok(),
        "a symlink to a 0644 file the user owns is as good as the file"
    );
}

// ---------------------------------------------------------------- ~/.k5login.d

#[test]
fn a_file_in_the_k5login_directory_can_allow_a_principal() {
    let home = Home::new("k5login-d");
    home.dir(".k5login.d");
    home.file(".k5login.d/staff", "bob@OTHER.REALM\n", 0o644);
    let users = Users::new("alice", &home);
    let grant = default_policy()
        .check(&users, &principal("bob@OTHER.REALM"), "alice")
        .expect("the directory is read after the file");
    assert_eq!(grant.rule, "USER-K5LOGIN");
    assert!(grant.reason.contains(".k5login.d"), "{}", grant.reason);
}

#[test]
fn editor_backups_in_the_k5login_directory_are_ignored() {
    // Heimdal skips `#names` and `name~`, so a half-written file cannot grant anything. This pins
    // that the file was skipped, not that it is absent: the matching line is in a `#` file.
    let home = Home::new("k5login-d-backup");
    home.file(".k5login.d/#staff", "bob@OTHER.REALM\n", 0o644);
    home.file(".k5login.d/staff~", "bob@OTHER.REALM\n", 0o644);
    let users = Users::new("alice", &home);
    let why = denial_text(default_policy().check(&users, &principal("bob@OTHER.REALM"), "alice"));
    assert!(
        !why.contains("bob@OTHER.REALM is alice"),
        "the principal must not have matched: {why}"
    );
    assert!(why.contains("no file in"), "{why}");
}

#[test]
fn a_subdirectory_of_the_k5login_directory_is_not_traversed() {
    let home = Home::new("k5login-d-nested");
    home.file(".k5login.d/nested/list", "bob@OTHER.REALM\n", 0o644);
    let users = Users::new("alice", &home);
    let why = denial_text(default_policy().check(&users, &principal("bob@OTHER.REALM"), "alice"));
    assert!(
        why.contains("is a directory") || why.contains("no file in"),
        "a nested file must not be read: {why}"
    );
}

// ---------------------------------------------------------------- configuration

#[test]
fn k5login_directory_moves_the_lookup_away_from_the_home_directory() {
    // A host serving users it has no local account for: `k5login_directory` is the way to point the
    // rule somewhere the administrator controls.
    let home = Home::new("k5login-directory-home");
    let lists = Home::new("k5login-directory-lists");
    // `k5login_directory` replaces the *home* directory, so the file is still `<dir>/.k5login`;
    // naming it after the user would be the `SYSTEM-K5LOGIN` layout, which is a different rule.
    lists.file(".k5login", "bob@OTHER.REALM\n", 0o644);
    let users = Users::new("alice", &home);
    let policy = Kuserok::from_conf(&conf(&format!(
        "[libdefaults]\n default_realm = {REALM}\n k5login_directory = {}\n",
        lists.path.display()
    )))
    .unwrap();
    let grant = policy
        .check(&users, &principal("bob@OTHER.REALM"), "alice")
        .expect("the file in the configured directory names it");
    assert_eq!(grant.rule, "USER-K5LOGIN");
}

#[test]
fn a_system_k5login_directory_is_one_file_per_user() {
    let home = Home::new("system-k5login");
    let sys = Home::new("system-k5login-sys");
    sys.file("alice", "bob@OTHER.REALM\n", 0o644);
    let users = Users::new("alice", &home);
    let policy = Kuserok::from_conf(&conf(&format!(
        "[libdefaults]\n default_realm = {REALM}\n kuserok = SYSTEM-K5LOGIN:{}\n",
        sys.path.display()
    )))
    .unwrap();
    assert_eq!(policy.rules(), vec!["SYSTEM-K5LOGIN"]);
    assert!(
        policy
            .check(&users, &principal("bob@OTHER.REALM"), "alice")
            .is_ok(),
        "the per-user file names the principal"
    );
    // A principal the file does not name: not authoritative, so this rule declines and there is
    // nothing after it — the chain ends in a refusal either way, and the reason must say so.
    let why = denial_text(policy.check(&users, &principal("carol@OTHER.REALM"), "alice"));
    assert!(why.contains("does not list it"), "{why}");
}

#[test]
fn a_system_k5login_without_a_directory_is_refused_at_the_configuration() {
    let err = Kuserok::from_conf(&conf(&format!(
        "[libdefaults]\n default_realm = {REALM}\n kuserok = SYSTEM-K5LOGIN\n"
    )))
    .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("needs its directory named"),
        "a guess at the sysconfdir would be a silent difference: {text}"
    );
}

#[test]
fn an_unknown_rule_name_is_refused_at_the_configuration() {
    // Heimdal declines an unknown name in every plugin and ends in a refusal; a deployment that
    // denies every login because of a typo is not something to find out from user reports.
    let err = Kuserok::from_conf(&conf(
        "[libdefaults]\n kuserok = USER-K5LOGIN, SIMPLE, FANCY-NEW-RULE\n",
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("not a rule this crate implements"), "{err}");
}

#[test]
fn the_chain_runs_in_the_order_it_is_written_and_deny_stops_it() {
    let home = Home::new("chain-order");
    home.file(".k5login", "alice@EXAMPLE.COM\n", 0o644);
    let users = Users::new("alice", &home);
    let policy = Kuserok::from_conf(&conf(&format!(
        "[libdefaults]\n default_realm = {REALM}\n kuserok = DENY, USER-K5LOGIN, SIMPLE\n"
    )))
    .unwrap();
    let why = denial_text(policy.check(&users, &principal("alice@EXAMPLE.COM"), "alice"));
    assert!(why.contains("DENY"), "{why}");
}

#[test]
fn the_domain_realm_makes_a_second_realm_local() {
    // A host that serves two realms says so in `[domain_realm]`, and SIMPLE then treats both as
    // local. Without this, every principal of the second realm needs a k5login file.
    let home = Home::new("domain-realm");
    let users = Users::new("alice", &home);
    let policy = Kuserok::from_conf(&conf(&format!(
        "[libdefaults]\n default_realm = {REALM}\n[domain_realm]\n .branch.example.com = BRANCH.EXAMPLE.COM\n"
    )))
    .unwrap();
    assert!(
        policy
            .check(&users, &principal("alice@BRANCH.EXAMPLE.COM"), "alice")
            .is_ok()
    );
    assert_eq!(
        policy.rules(),
        vec!["USER-K5LOGIN", "SIMPLE"],
        "the default chain is Heimdal's"
    );
}

// ---------------------------------------------------------------- the passwd file

#[test]
fn the_passwd_parser_reads_names_uids_and_homes_and_skips_what_it_cannot_read() {
    let db = PasswdFile::parse(
        "# comment\n\
         root:x:0:0:root:/root:/bin/sh\n\
         alice:x:1000:1000:Alice:/home/alice:/bin/bash\n\
         broken:x:notanumber:0::/nowhere:/bin/sh\n\
         nohome:x:1001:1001:::/bin/sh\n\
         short:x:1002\n",
    );
    assert_eq!(
        db.entries()
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        vec!["root", "alice"],
        "an unparsable uid or an empty home is skipped rather than guessed"
    );
    assert_eq!(db.uid("alice"), Some(1000));
    assert_eq!(db.home_dir("alice"), Some(PathBuf::from("/home/alice")));
    assert_eq!(db.uid("nobody"), None);
    assert_eq!(db.home_dir("nobody"), None);
}
