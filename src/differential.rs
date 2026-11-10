//! Differential test: this crate's key derivation and profile against `rrl-crypto`.
//!
//! The two implementations are meant to be the same functions. "Meant to be" is not a property
//! that holds by inspection — a duplicate that agrees on the vectors it was written from and
//! disagrees elsewhere produces tickets nobody can open, and the failure surfaces in the middle of
//! an authentication exchange rather than at a test.
//!
//! So every function is run twice on the same input and the octets compared: `n_fold`, `dr`, `dk`,
//! `derive_key`, `prf`, `string_to_key`, the CBC-CS3 block cipher, the RFC 3961 §5.3 profile and
//! its checksum. The inputs are deterministic and numerous rather than the published vectors: the
//! vectors are already covered on both sides, and what this file exists to catch is a difference
//! on the inputs nobody wrote a vector for.
//!
//! Cross-decryption is checked separately from ciphertext equality: a seal from one side must open
//! on the other. Ciphertext equality would pass even if both sides agreed on a wrong construction,
//! whereas an open failure is exactly what a client sees against a foreign KDC.

use crate::kdf::{self, Enctype as ForkEnctype, KeyUse as ForkUse};
use crate::nfold::n_fold as fork_n_fold;
use crate::profile;
use rrl_crypto::Enctype as TheirEnctype;
use rrl_crypto::kdf::{self as their_kdf, KeyUse as TheirUse};
use rrl_crypto::{aes_cts, nfold as their_nfold, profile as their_profile};

/// A deterministic byte generator: `splitmix64`, so a failure reproduces from the seed alone.
struct Bytes(u64);

impl Bytes {
    fn new(seed: u64) -> Self {
        Bytes(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn vec(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() >> 24) as u8).collect()
    }
}

/// The four enctypes, as each side names them.
const PAIRS: [(ForkEnctype, TheirEnctype); 4] = [
    (ForkEnctype::Aes128CtsHmacSha196, TheirEnctype::Aes128Sha1),
    (ForkEnctype::Aes256CtsHmacSha196, TheirEnctype::Aes256Sha1),
    (
        ForkEnctype::Aes128CtsHmacSha256128,
        TheirEnctype::Aes128Sha256,
    ),
    (
        ForkEnctype::Aes256CtsHmacSha384192,
        TheirEnctype::Aes256Sha384,
    ),
];

/// This crate has two enctypes — `kdf::Enctype` and `profile::Enctype` — that name the same wire
/// numbers. Bridging by number rather than by variant keeps the test honest about that: if the two
/// ever disagreed on a number, the bridge would fail here instead of silently testing one of them.
fn prof(e: ForkEnctype) -> profile::Enctype {
    profile::Enctype::from_i32(e.etype()).expect("an enctype the profile knows")
}

fn key_use(which: ForkUse) -> TheirUse {
    match which {
        ForkUse::Checksum => TheirUse::Checksum,
        ForkUse::Encryption => TheirUse::Encrypt,
        ForkUse::Integrity => TheirUse::Integrity,
    }
}

fn assert_same(what: &str, fork: Vec<u8>, their: Vec<u8>) {
    assert_eq!(
        hex(&fork),
        hex(&their),
        "{what}: the two implementations disagree"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `n_fold` over many input lengths and output sizes, including sizes that are not a multiple of
/// the input — where the bit rotation decides and an off-by-one shows.
#[test]
fn n_fold_agrees() {
    let mut rng = Bytes::new(1);
    for in_len in 1..=40usize {
        let input = rng.vec(in_len);
        for out_bits in [8usize, 16, 32, 64, 128, 168, 192, 256] {
            assert_same(
                &format!("n_fold({in_len} octets -> {out_bits} bits)"),
                fork_n_fold(&input, out_bits),
                their_nfold::n_fold(&input, out_bits),
            );
        }
    }
}

/// `DR` and `DK` at every key size the profiles use.
#[test]
fn dr_and_dk_agree() {
    let mut rng = Bytes::new(2);
    for key_len in [16usize, 32] {
        let base = rng.vec(key_len);
        for constant in [
            vec![0x00u8, 0xAA],
            vec![0x01, 0x80],
            vec![0x55, 0x55],
            vec![0xFF, 0xFF],
        ] {
            for k in [16usize, 21, 24, 32] {
                assert_same(
                    &format!("dr(key {key_len}, out {k})"),
                    kdf::dr(&base, &constant, k).expect("dr"),
                    their_kdf::dr(&base, &constant, k).expect("dr"),
                );
                assert_same(
                    &format!("dk(key {key_len}, out {k})"),
                    kdf::dk(&base, &constant, k).expect("dk"),
                    their_kdf::dk(&base, &constant, k).expect("dk"),
                );
            }
        }
    }
}

/// `derive_key` for every enctype, every key use, and a spread of usages including the ones this
/// crate actually emits on the wire (2, 3, 8, 23, 25, 54-57).
#[test]
fn derive_key_agrees() {
    let mut rng = Bytes::new(3);
    for (fork_e, their_e) in PAIRS {
        let base = rng.vec(fork_e.key_size());
        for usage in [1u32, 2, 3, 4, 8, 9, 11, 23, 25, 26, 27, 54, 55, 56, 57, 65] {
            for which in [ForkUse::Encryption, ForkUse::Integrity, ForkUse::Checksum] {
                assert_same(
                    &format!("derive_key({fork_e:?}, usage {usage}, {which:?})"),
                    kdf::derive_key(fork_e, &base, usage, which).expect("derive_key"),
                    their_kdf::derive_key(their_e, &base, usage, key_use(which))
                        .expect("derive_key"),
                );
            }
        }
    }
}

/// `PRF+` (RFC 6113 §5.1) decides how much of the output is kept; a truncation difference shows
/// here and nowhere else.
#[test]
fn prf_agrees() {
    let mut rng = Bytes::new(4);
    for (fork_e, their_e) in PAIRS {
        let key = rng.vec(fork_e.key_size());
        for len in [0usize, 1, 15, 16, 20, 32, 33, 64] {
            let input = rng.vec(len);
            assert_same(
                &format!("prf({fork_e:?}, {len} octets)"),
                kdf::prf(fork_e, &key, &input).expect("prf"),
                their_kdf::prf(their_e, &key, &input).expect("prf"),
            );
        }
    }
}

/// Password-to-key, with and without `s2kparams`: the iteration count is read two different ways
/// by the two implementations (`[u8; 4]` and a slice), and the parse is where they can part.
#[test]
fn string_to_key_agrees() {
    for (fork_e, their_e) in PAIRS {
        for password in [
            "",
            "password",
            "correct horse battery staple",
            "\u{00e9}clair",
        ] {
            for salt in [
                b"ATHENA.MIT.EDUraeburn".as_slice(),
                b"x".as_slice(),
                b"".as_slice(),
            ] {
                for params in [None, Some(4096u32), Some(1)] {
                    let fork = kdf::string_to_key(
                        fork_e,
                        password.as_bytes(),
                        salt,
                        params.map(u32::to_be_bytes),
                    );
                    let their = their_kdf::s2k(
                        their_e,
                        password.as_bytes(),
                        salt,
                        params
                            .map(|p| p.to_be_bytes())
                            .as_ref()
                            .map(|b| b.as_slice()),
                    );
                    match (fork, their) {
                        (Ok(a), Ok(b)) => assert_same(
                            &format!("string_to_key({fork_e:?}, {password:?}, {params:?})"),
                            a,
                            b,
                        ),
                        (Err(a), Err(b)) => assert_eq!(
                            a.to_string().is_empty(),
                            b.to_string().is_empty(),
                            "both sides must refuse, with a reason"
                        ),
                        (a, b) => panic!(
                            "string_to_key({fork_e:?}, {password:?}, {params:?}): one side \
                             refused and the other did not: {a:?} vs {b:?}"
                        ),
                    }
                }
            }
        }
    }
}

/// The block cipher alone, at the lengths where CBC-CS3 does something other than CBC: a single
/// block, exactly two blocks, and a last block of exactly one octet.
#[test]
fn aes_cts_agrees() {
    let mut rng = Bytes::new(5);
    for key_len in [16usize, 32] {
        let key = rng.vec(key_len);
        for len in [16usize, 17, 31, 32, 33, 48, 63, 64] {
            let data = rng.vec(len);
            let fork = profile::aes_cts_encrypt(&key, &[0u8; 16], &data).expect("cts encrypt");
            let their = aes_cts::encrypt(&key, &[0u8; 16], &data).expect("cts encrypt");
            assert_same(
                &format!("aes_cts_encrypt({key_len}-octet key, {len} octets)"),
                fork.clone(),
                their.clone(),
            );

            assert_same(
                &format!("aes_cts_decrypt({len} octets)"),
                profile::aes_cts_decrypt(&key, &[0u8; 16], &fork).expect("cts decrypt"),
                aes_cts::decrypt(&key, &[0u8; 16], &their).expect("cts decrypt"),
            );
        }
    }
}

/// The whole profile, with the confounder fixed so the output is comparable, then opened by the
/// other side. The second half is the part that matters: two implementations that agree on a wrong
/// construction still pass the first.
#[test]
fn the_profile_agrees_and_cross_opens() {
    let mut rng = Bytes::new(6);
    for (fork_e, their_e) in PAIRS {
        let pe = prof(fork_e);
        let ke = rng.vec(pe.ke_len());
        let ki = rng.vec(pe.ki_len());
        for len in [0usize, 1, 15, 16, 17, 32, 33, 100, 1000] {
            let plain = rng.vec(len);
            let conf = rng.vec(16);

            let fork = profile::encrypt_with_confounder(prof(fork_e), &ke, &ki, &conf, &plain)
                .expect("fork encrypt");
            let their = their_profile::encrypt_with_confounder(their_e, &ke, &ki, &conf, &plain)
                .expect("their encrypt");
            assert_same(
                &format!("encrypt({fork_e:?}, {len} octets)"),
                fork.clone(),
                their.clone(),
            );

            assert_same(
                &format!("fork opens their ciphertext ({len} octets)"),
                profile::decrypt(prof(fork_e), &ke, &ki, &their).expect("fork decrypt"),
                plain.clone(),
            );
            assert_same(
                &format!("they open fork ciphertext ({len} octets)"),
                their_profile::decrypt(their_e, &ke, &ki, &fork).expect("their decrypt"),
                plain,
            );
        }
    }
}

/// The keyed checksum, and each side verifying the other's tag.
#[test]
fn checksum_agrees_and_cross_verifies() {
    let mut rng = Bytes::new(7);
    for (fork_e, their_e) in PAIRS {
        let kc = rng.vec(prof(fork_e).kc_len());
        for len in [0usize, 1, 16, 100] {
            let data = rng.vec(len);
            let fork = profile::checksum(prof(fork_e), &kc, &data).expect("fork checksum");
            let their = their_profile::checksum(their_e, &kc, &data).expect("their checksum");
            assert_same(
                &format!("checksum({fork_e:?}, {len} octets)"),
                fork.clone(),
                their.clone(),
            );

            assert!(
                profile::verify_checksum(prof(fork_e), &kc, &data, &their).expect("verify"),
                "fork must accept their tag ({fork_e:?})"
            );
            their_profile::verify_checksum(their_e, &kc, &data, &fork).expect("verify");

            let mut broken = their.clone();
            broken[0] ^= 0x01;
            assert!(
                !profile::verify_checksum(prof(fork_e), &kc, &data, &broken).expect("verify"),
                "a changed tag must not verify ({fork_e:?})"
            );
        }
    }
}
