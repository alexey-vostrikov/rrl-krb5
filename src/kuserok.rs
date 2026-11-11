//! `krb5_kuserok`: may this principal log in as this local user?
//!
//! The last step of `recvauth`. A service that has just proved a ticket knows a *principal*
//! (`alice@EXAMPLE.COM`); the operating system knows *users* (`bob`). Between them sits a policy
//! that nobody can guess: a host may accept the realm's principals, or only some of them, or only
//! through a file the user wrote. This module is that policy, and it is Heimdal's
//! (`lib/krb5/kuserok.c`) down to the order the rules run in.
//!
//! # The rules
//!
//! `[libdefaults] kuserok` names them; when it is absent the chain is `USER-K5LOGIN` and then
//! `SIMPLE`, which is Heimdal's default. Each rule either decides the question or declines to, and
//! the first one that decides wins:
//!
//! * **`USER-K5LOGIN`** — `~/.k5login`, then every file in `~/.k5login.d`, each listing one
//!   principal per line. A match allows. A file that exists but is unusable — a directory, a
//!   symlink to something untrustworthy, wrong owner, writable by group or other — is not a match
//!   either, but it still counts as "the user has a k5login", which is what makes
//!   `k5login_authoritative` bite.
//! * **`SIMPLE`** — a one-component principal whose name is the local user and whose realm is a
//!   local realm (the default realm, or a realm `[domain_realm]` names). This is what makes
//!   `alice@EXAMPLE.COM` able to log in as `alice` on a host of that realm with no file at all.
//! * **`SYSTEM-K5LOGIN:<dir>`** — one file per user in a directory the administrator owns, so a
//!   home directory that is not writable (or not present) is not a problem.
//! * **`DENY`** — always refuses, for a chain that ends in a stop.
//!
//! # What is deliberately different from Heimdal
//!
//! * **No plugins.** Heimdal's rules are plugins, and a name it does not know is declined by every
//!   plugin and ends in a refusal. Here an unknown rule name is an error when the policy is built,
//!   because a typo in `kuserok` that silently denies every login is the sort of deployment nobody
//!   debugs in time.
//! * **`SYSTEM-K5LOGIN` without a directory is an error.** Heimdal falls back to
//!   `SYSCONFDIR/k5login.d`, a path fixed at *its* build time; this crate has no such path to
//!   inherit, and guessing `/etc/k5login.d` would be a silent difference. Either name the
//!   directory or set `k5login_directory`.
//! * **`~luser` is resolved through [`LocalUsers`], not `getpwnam`.** A library that shells out to
//!   NSS cannot be tested without a user database; the embedder passes what it has. [`PasswdFile`]
//!   is the plain `/etc/passwd` reading, which is enough for a host without SSSD.
//!
//! # Symlinks
//!
//! A `.k5login` that is a symlink is followed, as Heimdal follows it (`fopen`, then `fstat` on the
//! open file). What is checked is therefore the *file's* owner and mode, and a link to a file the
//! user can make group-writable is refused — that is the property that matters, and inventing a
//! "no symlinks" rule Heimdal does not have would break setups that link one file into several
//! home directories.

use std::path::{Path, PathBuf};

use rrl_krb_common::name::Principal;

use crate::config::{ConfigError, Krb5Conf};

/// The local user database a policy consults.
///
/// Two facts are needed and nothing else: where the user's home directory is, and which numeric
/// owner a k5login file must have. Both come from `getpwnam` in Heimdal; here they come from
/// whatever the embedder has.
pub trait LocalUsers {
    /// `~luser`, or `None` when the system does not know the user.
    fn home_dir(&self, luser: &str) -> Option<PathBuf>;
    /// The uid of `luser`, or `None` when the system does not know the user.
    fn uid(&self, luser: &str) -> Option<u32>;
}

/// One entry of a passwd database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    /// The login name.
    pub name: String,
    /// `pw_uid`.
    pub uid: u32,
    /// `pw_dir`.
    pub home: PathBuf,
}

/// `/etc/passwd`, parsed.
///
/// NSS is not consulted: this is the file, and a host whose users come from LDAP or SSSD needs an
/// embedder-supplied [`LocalUsers`] instead. That is a real difference from `getpwnam`, and it is
/// named here rather than hidden — a server that authenticates domain users usually has no local
/// accounts at all, which is exactly when `SYSTEM-K5LOGIN` is the rule to configure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasswdFile {
    entries: Vec<PasswdEntry>,
}

impl PasswdFile {
    /// Parses passwd-format text: `name:passwd:uid:gid:gecos:home:shell`, `#` comments and blank
    /// lines ignored. Entries whose uid or home field is missing or unparsable are skipped rather
    /// than guessed at.
    pub fn parse(text: &str) -> Self {
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 6 {
                continue;
            }
            let (Ok(uid), false) = (fields[2].parse::<u32>(), fields[5].is_empty()) else {
                continue;
            };
            entries.push(PasswdEntry {
                name: fields[0].to_owned(),
                uid,
                home: PathBuf::from(fields[5]),
            });
        }
        Self { entries }
    }

    /// Reads the host's `/etc/passwd`.
    pub fn system() -> std::io::Result<Self> {
        Ok(Self::parse(&std::fs::read_to_string("/etc/passwd")?))
    }

    /// The entries, in file order.
    pub fn entries(&self) -> &[PasswdEntry] {
        &self.entries
    }
}

impl LocalUsers for PasswdFile {
    fn home_dir(&self, luser: &str) -> Option<PathBuf> {
        self.entries
            .iter()
            .find(|e| e.name == luser)
            .map(|e| e.home.clone())
    }

    fn uid(&self, luser: &str) -> Option<u32> {
        self.entries.iter().find(|e| e.name == luser).map(|e| e.uid)
    }
}

/// One rule of the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    Simple,
    UserK5login,
    /// `/etc`-style directory of per-user files; the directory is explicit, see the module docs.
    SystemK5login(PathBuf),
    Deny,
}

impl Rule {
    fn name(&self) -> &'static str {
        match self {
            Rule::Simple => "SIMPLE",
            Rule::UserK5login => "USER-K5LOGIN",
            Rule::SystemK5login(_) => "SYSTEM-K5LOGIN",
            Rule::Deny => "DENY",
        }
    }
}

/// What a rule decided, or that it declined.
#[derive(Debug)]
enum Step {
    Allow(String),
    Deny(String),
    /// This rule has nothing to say; the next one decides.
    Next,
}

/// Who allowed the login, and on what grounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The rule that allowed it.
    pub rule: String,
    /// One sentence saying what matched, for the audit log.
    pub reason: String,
}

/// Why the login is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// The rule that refused, or the last rule in the chain when every one declined.
    pub rule: String,
    /// What was checked and what was found. An operator reading only "access denied" in a log has
    /// to guess which of four rules refused.
    pub reason: String,
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} refused: {}", self.rule, self.reason)
    }
}

impl std::error::Error for Denial {}

/// The `kuserok` policy of one configuration.
#[derive(Debug, Clone)]
pub struct Kuserok {
    rules: Vec<Rule>,
    /// `k5login_authoritative`: a k5login that exists and does not list the principal is a refusal
    /// rather than a fall-through. Off by default, as in Heimdal.
    authoritative: bool,
    /// `k5login_directory`: where `USER-K5LOGIN` looks instead of the home directory, which is how
    /// a host serves users it has no local account for.
    k5login_directory: Option<PathBuf>,
    /// The realms this host considers its own, for [`Rule::Simple`].
    local_realms: Vec<String>,
    /// `[libdefaults] default_realm`, for a k5login line that names a principal without a realm.
    default_realm: Option<String>,
}

impl Kuserok {
    /// The policy `conf` describes. With no `[libdefaults] kuserok`, Heimdal's default chain:
    /// `USER-K5LOGIN`, then `SIMPLE`.
    pub fn from_conf(conf: &Krb5Conf) -> Result<Self, ConfigError> {
        let raw = conf.get_all(&["libdefaults", "kuserok"]);
        let names: Vec<&str> = raw
            .iter()
            .flat_map(|v| v.split(|c: char| c == ',' || c.is_whitespace()))
            .filter(|s| !s.is_empty())
            .collect();
        let rules = if names.is_empty() {
            vec![Rule::UserK5login, Rule::Simple]
        } else {
            names
                .iter()
                .map(|name| Self::rule_named(name))
                .collect::<Result<Vec<_>, _>>()?
        };
        Ok(Self {
            rules,
            authoritative: conf
                .get(&["libdefaults", "k5login_authoritative"])
                .map(|v| crate::config::parse_bool(v).unwrap_or(false))
                .unwrap_or(false),
            k5login_directory: conf
                .get(&["libdefaults", "k5login_directory"])
                .map(PathBuf::from),
            local_realms: conf.local_realms(),
            default_realm: conf.default_realm().map(str::to_owned),
        })
    }

    fn rule_named(name: &str) -> Result<Rule, ConfigError> {
        const KNOWN: &str = "SIMPLE, USER-K5LOGIN, SYSTEM-K5LOGIN:<dir>, DENY";
        if name.eq_ignore_ascii_case("SIMPLE") {
            return Ok(Rule::Simple);
        }
        if name.eq_ignore_ascii_case("USER-K5LOGIN") {
            return Ok(Rule::UserK5login);
        }
        if name.eq_ignore_ascii_case("DENY") {
            return Ok(Rule::Deny);
        }
        if let Some(rest) = name
            .strip_prefix("SYSTEM-K5LOGIN:")
            .or_else(|| name.strip_prefix("system-k5login:"))
        {
            if rest.is_empty() {
                return Err(ConfigError::BadValue {
                    tag: "kuserok".into(),
                    value: name.into(),
                    why: "SYSTEM-K5LOGIN needs a directory after the colon".into(),
                });
            }
            return Ok(Rule::SystemK5login(PathBuf::from(rest)));
        }
        if name.eq_ignore_ascii_case("SYSTEM-K5LOGIN") {
            return Err(ConfigError::BadValue {
                tag: "kuserok".into(),
                value: name.into(),
                why: "SYSTEM-K5LOGIN needs its directory named: this crate has no build-time \
                      sysconfdir to fall back to, and guessing one would be a silent difference. \
                      Write SYSTEM-K5LOGIN:/etc/k5login.d, or set k5login_directory."
                    .into(),
            });
        }
        Err(ConfigError::BadValue {
            tag: "kuserok".into(),
            value: name.into(),
            why: format!("not a rule this crate implements; known: {KNOWN}"),
        })
    }

    /// The rules, in the order they run.
    pub fn rules(&self) -> Vec<&'static str> {
        self.rules.iter().map(Rule::name).collect()
    }

    /// Whether `principal` may log in as `luser`.
    ///
    /// `Err` is a refusal with the rule and the reason; it is not an I/O failure — a k5login that
    /// cannot be read is a refusal of that file, not a refusal to answer.
    pub fn check(
        &self,
        users: &dyn LocalUsers,
        principal: &Principal,
        luser: &str,
    ) -> Result<Grant, Denial> {
        let mut notes: Vec<String> = Vec::new();
        for rule in &self.rules {
            match self.apply(rule, users, principal, luser, &mut notes) {
                Step::Allow(reason) => {
                    return Ok(Grant {
                        rule: rule.name().to_owned(),
                        reason,
                    });
                }
                Step::Deny(reason) => {
                    return Err(Denial {
                        rule: rule.name().to_owned(),
                        reason,
                    });
                }
                Step::Next => {}
            }
        }
        Err(Denial {
            rule: self
                .rules
                .last()
                .map(Rule::name)
                .unwrap_or("no rule")
                .to_owned(),
            reason: if notes.is_empty() {
                format!(
                    "{} may not log in as {luser}: no rule allowed it ({})",
                    principal,
                    self.rules()
                        .iter()
                        .map(|r| (*r).to_owned())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                format!(
                    "{} may not log in as {luser}: {}",
                    principal,
                    notes.join("; ")
                )
            },
        })
    }

    fn apply(
        &self,
        rule: &Rule,
        users: &dyn LocalUsers,
        principal: &Principal,
        luser: &str,
        notes: &mut Vec<String>,
    ) -> Step {
        match rule {
            Rule::Deny => Step::Deny("the DENY rule is in the kuserok chain".into()),
            Rule::Simple => self.simple(principal, luser, notes),
            Rule::UserK5login => self.user_k5login(users, principal, luser, notes),
            Rule::SystemK5login(dir) => {
                let path = dir.join(luser);
                match self.file_at(&path, None, principal) {
                    Outcome::Match => Step::Allow(format!("{} lists it", path.display())),
                    Outcome::Absent | Outcome::Unusable(_) => Step::Next,
                    Outcome::NoMatch => {
                        if self.authoritative {
                            Step::Deny(format!(
                                "{} does not list it, and k5login_authoritative is set",
                                path.display()
                            ))
                        } else {
                            notes.push(format!("{} does not list it", path.display()));
                            Step::Next
                        }
                    }
                }
            }
        }
    }

    /// `SIMPLE`: a one-component principal, named like the user, in a local realm.
    fn simple(&self, principal: &Principal, luser: &str, notes: &mut Vec<String>) -> Step {
        if principal.components.len() != 1 {
            notes.push(format!(
                "{} has {} components, and SIMPLE matches one-component principals only",
                principal,
                principal.components.len()
            ));
            return Step::Next;
        }
        if principal.components[0] != luser {
            notes.push(format!("{} is not named {luser}", principal.components[0]));
            return Step::Next;
        }
        if !self.local_realms.contains(&principal.realm) {
            notes.push(format!(
                "{} is not a realm this host counts as local ({})",
                principal.realm,
                if self.local_realms.is_empty() {
                    "none: no default_realm and no domain_realm".to_owned()
                } else {
                    self.local_realms.join(", ")
                }
            ));
            return Step::Next;
        }
        Step::Allow(format!("{} is {luser} in a local realm", principal))
    }

    /// `USER-K5LOGIN`: `~/.k5login`, then `~/.k5login.d`.
    fn user_k5login(
        &self,
        users: &dyn LocalUsers,
        principal: &Principal,
        luser: &str,
        notes: &mut Vec<String>,
    ) -> Step {
        let dir = match &self.k5login_directory {
            Some(dir) => dir.clone(),
            None => match users.home_dir(luser) {
                Some(home) => home,
                None => {
                    notes.push(format!("no home directory for {luser}"));
                    return Step::Next;
                }
            },
        };
        let owner = users.uid(luser);
        let file = dir.join(".k5login");
        let mut found = false;
        match self.file_at(&file, owner, principal) {
            Outcome::Match => return Step::Allow(format!("{} lists it", file.display())),
            Outcome::NoMatch => {
                found = true;
                notes.push(format!("{} does not list it", file.display()));
            }
            Outcome::Unusable(why) => {
                found = true;
                notes.push(format!("{}: {why}", file.display()));
            }
            Outcome::Absent => {}
        }

        let d = dir.join(".k5login.d");
        match self.directory_at(&d, owner, principal) {
            Outcome::Match => {
                return Step::Allow(format!("a file in {} lists it", d.display()));
            }
            Outcome::NoMatch => {
                found = true;
                notes.push(format!("no file in {} lists it", d.display()));
            }
            Outcome::Unusable(why) => {
                found = true;
                notes.push(format!("{}: {why}", d.display()));
            }
            Outcome::Absent => {}
        }

        if found && self.authoritative {
            // The user has a k5login, and it does not name this principal: that is a decision, not
            // an absence. This is the whole point of the option (Heimdal `kuserok.c`).
            //
            // The notes carry what was actually found — a mode, an owner, a file that lists
            // somebody else — because "an authoritative k5login refused it" is not something an
            // operator can act on, and the file they must fix is the one named there.
            return Step::Deny(format!(
                "k5login_authoritative is set and nothing this user has lists it ({})",
                notes.join("; ")
            ));
        }
        Step::Next
    }

    /// Every file in a `.k5login.d` directory, in the order the filesystem lists them.
    ///
    /// Heimdal skips `.`, `..`, names starting with `#` (editor autosave) and names ending in `~`
    /// (editor backup), and does not descend into subdirectories. Subdirectories are skipped here
    /// for the same reason: a directory in a directory of principal lists is a mistake, not a
    /// nesting.
    fn directory_at(&self, dir: &Path, owner: Option<u32>, principal: &Principal) -> Outcome {
        let meta = match std::fs::metadata(dir) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Outcome::Absent,
            Err(e) => return Outcome::Unusable(format!("cannot be read: {e}")),
        };
        if !meta.is_dir() {
            return Outcome::Unusable("is not a directory".into());
        }
        if let Some(why) = unix_trust(&meta, owner) {
            return Outcome::Unusable(why);
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => return Outcome::Unusable(format!("cannot be listed: {e}")),
        };
        let mut unusable: Option<String> = None;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.starts_with('#') || name.ends_with('~') {
                continue;
            }
            let path = entry.path();
            match self.file_at(&path, owner, principal) {
                Outcome::Match => return Outcome::Match,
                Outcome::Absent | Outcome::NoMatch => {}
                Outcome::Unusable(why) => {
                    unusable.get_or_insert(format!("{name}: {why}"));
                }
            }
        }
        // A directory whose every file was unusable has still been looked at, and the reason is
        // worth carrying: "no file in ~/.k5login.d lists it" would hide that the file which does
        // was refused for its mode, which is the one fact an operator needs.
        match unusable {
            Some(why) => Outcome::Unusable(why),
            None => Outcome::NoMatch,
        }
    }

    /// One k5login file: present, usable, and whether it names `principal`.
    ///
    /// `owner` is the uid the file must belong to (root is always acceptable, as in Heimdal); `None`
    /// means the caller has no local user to compare against and the ownership check is skipped —
    /// that is `SYSTEM-K5LOGIN`, whose directory the administrator already controls.
    fn file_at(&self, path: &Path, owner: Option<u32>, principal: &Principal) -> Outcome {
        let meta = match std::fs::metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Outcome::Absent,
            Err(e) => return Outcome::Unusable(format!("cannot be read: {e}")),
        };
        if meta.is_dir() {
            return Outcome::Unusable("is a directory, not a list of principals".into());
        }
        if let Some(why) = unix_trust(&meta, owner) {
            return Outcome::Unusable(why);
        }
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) => return Outcome::Unusable(format!("cannot be read: {e}")),
        };
        if self.lists(&text, principal) {
            Outcome::Match
        } else {
            Outcome::NoMatch
        }
    }

    /// Whether a k5login file names `principal`.
    ///
    /// One principal per line, `#` starts a comment, blank lines are ignored, and a line that is not
    /// a principal is skipped — Heimdal skips it too, and a line that cannot be parsed can only
    /// deny, so skipping is the safe reading. A name without a realm takes `default_realm`, which is
    /// what `krb5_parse_name` does.
    fn lists(&self, text: &str, principal: &Principal) -> bool {
        text.lines().any(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return false;
            }
            let candidate = match line.rsplit_once('@') {
                Some(_) => Principal::parse(line).ok(),
                None => self
                    .default_realm
                    .as_deref()
                    .and_then(|realm| Principal::parse_in_realm(line, realm).ok()),
            };
            candidate.is_some_and(|c| {
                // Identity, not spelling: the name type a parser inferred from the number of
                // components is not part of who the principal is.
                c.realm == principal.realm && c.components == principal.components
            })
        })
    }
}

/// What one file or directory turned out to be.
#[derive(Debug)]
enum Outcome {
    /// Not there at all.
    Absent,
    /// There, and names the principal.
    Match,
    /// There, readable, and does not name the principal.
    NoMatch,
    /// There, and must not be trusted: wrong owner, wrong mode, a directory where a file belongs.
    Unusable(String),
}

/// The ownership and mode a k5login file must have, or `None` when it does.
///
/// Heimdal's `check_owner_file`: not writable by group or other, owned by the user or by root. A
/// file that anybody in the user's group can rewrite is a file that anybody in that group can use to
/// grant themselves the user's Kerberos identity, which is the whole attack this check exists for.
#[cfg(unix)]
fn unix_trust(meta: &std::fs::Metadata, owner: Option<u32>) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode();
    if mode & 0o022 != 0 {
        return Some(format!(
            "is writable by group or other (mode {:04o})",
            mode & 0o7777
        ));
    }
    if let Some(owner) = owner
        && meta.uid() != owner
        && meta.uid() != 0
    {
        return Some(format!(
            "is owned by uid {}, and must be owned by uid {owner} or root",
            meta.uid()
        ));
    }
    None
}

/// Ownership and mode cannot be established on a platform without them, and a k5login that cannot
/// be checked is a k5login that must not be trusted — Heimdal declines the rule on Windows for the
/// same reason (`kuserok.c`, the `_WIN32` branch of `check_owner_file`).
#[cfg(not(unix))]
fn unix_trust(_meta: &std::fs::Metadata, _owner: Option<u32>) -> Option<String> {
    Some("ownership and mode cannot be checked on this platform".to_owned())
}

#[cfg(test)]
mod tests;
