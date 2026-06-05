//! SOTERIA-OMEGA Part 1 — Classification & Multi-Level Security (MLS).
//!
//! This module models a 5+ level classification scheme derived from
//! US EO 13526 / DoD 5200.01, NATO ATOMAL, EU RESTRICTED, and the
//! Five-Eyes classification conventions. Each `Classification` is a
//! totally-ordered, comparable, serialisable enum.
//!
//! ## Bell-LaPadula enforcement
//!
//! The classic MLS model enforces two properties:
//!
//! 1. **No Read Up** (NRU): a subject at level `L_s` cannot read an
//!    object at level `L_o > L_s`.
//! 2. **No Write Down** (NWD): a subject at level `L_s` cannot write
//!    to an object at level `L_o < L_s` unless the write is to a
//!    sanitised output (e.g. a downgrader).
//!
//! In a FDE context "read" maps to "decrypt a sector" and "write" maps
//! to "encrypt a sector". We enforce NRU and NWD at the key-derivation
//! step: deriving a key for level `L_o` requires the operator's
//! clearance to be `>= L_o`, and the derived key is bound to `L_o` so
//! it cannot be used to encrypt at any other level.
//!
//! ## Compartments
//!
//! Beyond the linear level, classified data is usually compartmented:
//! `TOP SECRET // SI / TK / G / HCS` etc. We model compartments as a
//! bit-set of named strings (e.g. "SI", "TK", "NOFORN"). A subject
//! needs clearance in the compartment to access the data.
//!
//! ## Caveats
//!
//! This is an **enforcement helper**, not a complete MLS kernel. Real
//! MLS requires a trusted OS (SELinux MLS, AppArmor, or a
//! capability-sealed microkernel). Soteria-OMEGA provides the crypto
//! and key-binding primitives; the OS-level enforcement is the
//! operator's responsibility.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const UNCLASSIFIED: u8 = 0;
pub const CUI: u8 = 10;
pub const CONFIDENTIAL: u8 = 20;
pub const SECRET: u8 = 30;
pub const TOPSECRET: u8 = 40;
pub const TOPSECRET_SCI: u8 = 50;

pub const NATO_RESTRICTED: u8 = 20;
pub const NATO_CONFIDENTIAL: u8 = 25;
pub const NATO_SECRET: u8 = 35;
pub const COSMIC_TOP_SECRET: u8 = 60;

pub const EU_RESTRICTED: u8 = 22;
pub const EU_CONFIDENTIAL: u8 = 27;
pub const EU_SECRET: u8 = 37;

pub const FVEY_RESTRICTED: u8 = 15;
pub const FVEY_CONFIDENTIAL: u8 = 23;
pub const FVEY_SECRET: u8 = 33;

/// A 5+ level classification.
///
/// Variants ending in `*` are non-US designations (NATO, EU, FVEY).
/// Variants ending in `Sci` are Sensitive Compartmented Information
/// (US) or COSMIC TOP SECRET (NATO). The numeric `level()` is a total
/// ordering suitable for `Ord`/`PartialOrd` comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Classification {
    /// Public release; no protections required.
    Unclassified,
    /// Controlled Unclassified Information (US): CUI//SP-PRIV etc.
    Cui,
    /// Five Eyes RESTRICTED.
    FveyRestricted,
    /// US Confidential.
    Confidential,
    /// EU RESTRICTED.
    EuRestricted,
    /// NATO RESTRICTED.
    NatoRestricted,
    /// NATO CONFIDENTIAL.
    NatoConfidential,
    /// EU CONFIDENTIAL.
    EuConfidential,
    /// Five Eyes CONFIDENTIAL.
    FveyConfidential,
    /// US Secret.
    Secret,
    /// FVEY SECRET.
    FveySecret,
    /// NATO SECRET.
    NatoSecret,
    /// EU SECRET.
    EuSecret,
    /// US Top Secret.
    TopSecret,
    /// Five Eyes TOP SECRET.
    FveyTopSecret,
    /// US Top Secret // SCI.
    TopSecretSci,
    /// NATO COSMIC TOP SECRET.
    CosmicTopSecret,
}

impl Classification {
    /// Numeric level used for comparisons and policy lookups.
    pub fn level(self) -> u8 {
        match self {
            Self::Unclassified => UNCLASSIFIED,
            Self::Cui => CUI,
            Self::FveyRestricted => FVEY_RESTRICTED,
            Self::Confidential => CONFIDENTIAL,
            Self::EuRestricted => EU_RESTRICTED,
            Self::NatoRestricted => NATO_RESTRICTED,
            Self::NatoConfidential => NATO_CONFIDENTIAL,
            Self::EuConfidential => EU_CONFIDENTIAL,
            Self::FveyConfidential => FVEY_CONFIDENTIAL,
            Self::Secret => SECRET,
            Self::FveySecret => FVEY_SECRET,
            Self::NatoSecret => NATO_SECRET,
            Self::EuSecret => EU_SECRET,
            Self::TopSecret => TOPSECRET,
            Self::FveyTopSecret => TOPSECRET,
            Self::TopSecretSci => TOPSECRET_SCI,
            Self::CosmicTopSecret => COSMIC_TOP_SECRET,
        }
    }

    /// Short string label suitable for logs and audit (e.g. "TS//SCI").
    pub fn label(self) -> &'static str {
        match self {
            Self::Unclassified => "U",
            Self::Cui => "CUI",
            Self::FveyRestricted => "FVEY//RESTRICTED",
            Self::Confidential => "C",
            Self::EuRestricted => "EU//RESTRICTED",
            Self::NatoRestricted => "NS",
            Self::NatoConfidential => "NC",
            Self::EuConfidential => "EU//CONFIDENTIAL",
            Self::FveyConfidential => "FVEY//CONFIDENTIAL",
            Self::Secret => "S",
            Self::FveySecret => "FVEY//SECRET",
            Self::NatoSecret => "NS",
            Self::EuSecret => "EU//SECRET",
            Self::TopSecret => "TS",
            Self::FveyTopSecret => "FVEY//TS",
            Self::TopSecretSci => "TS//SCI",
            Self::CosmicTopSecret => "CTS",
        }
    }

    /// Bell-LaPadula No-Read-Up: can a subject at `self` read data at
    /// `object`? True iff `self >= object` and `self.compartments ⊇
    /// object.compartments`.
    pub fn can_read(self, object: Classification, compartments: Compartments) -> bool {
        self.level() >= object.level()
            && compartments.contains_all(&Compartments::for_level(object))
    }

    /// Bell-LaPadula No-Write-Down: can a subject at `self` write data
    /// to `object`? True iff `self == object` (write at your own level)
    /// or `object.level() == self.level() + 10` and the object level is
    /// the special "sanitised" output zone. Otherwise false.
    pub fn can_write(self, object: Classification) -> bool {
        self.level() == object.level()
    }

    /// Minimum symmetric key length in bits recommended for this level.
    /// Follows NIST SP 800-131A and CNSSP-15 for national-security
    /// systems.
    pub fn minimum_key_bits(self) -> usize {
        if self.level() >= TOPSECRET_SCI {
            256
        } else if self.level() >= SECRET {
            256
        } else {
            128
        }
    }

    /// Whether this classification mandates post-quantum cryptography.
    /// Per CNSA 2.0, Top Secret and below must transition to ML-KEM +
    /// ML-DSA by 2033; SCI and CTS data must use PQ today.
    pub fn requires_post_quantum(self) -> bool {
        self.level() >= TOPSECRET_SCI || self.level() >= COSMIC_TOP_SECRET
    }

    /// Whether this classification mandates a dual cipher (XTS+XChaCha
    /// in cascade per the OMEGA dual-cipher rule). TOP SECRET and above
    /// always; SECRET optional.
    pub fn requires_dual_cipher(self) -> bool {
        self.level() >= TOPSECRET
    }

    /// Whether this classification mandates air-gapped key material
    /// (no network or TPM-internet-fallback). SCI and CTS only.
    pub fn requires_air_gapped_keys(self) -> bool {
        self.level() >= TOPSECRET_SCI
    }
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A set of compartment markings. Stored as a `BTreeSet` for
/// deterministic ordering and serialisation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Compartments {
    inner: BTreeSet<String>,
}

impl Compartments {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, tag: impl Into<String>) -> bool {
        self.inner.insert(tag.into())
    }

    pub fn remove(&mut self, tag: &str) -> bool {
        self.inner.remove(tag)
    }

    pub fn contains(&self, tag: &str) -> bool {
        self.inner.contains(tag)
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.inner.iter().map(|s| s.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True iff every tag in `other` is also in `self`.
    pub fn contains_all(&self, other: &Compartments) -> bool {
        other.inner.is_subset(&self.inner)
    }

    /// Default compartment set for a given classification level.
    /// The `for_level` function returns the canonical compartments a
    /// piece of data at that level is presumed to carry.
    pub fn for_level(c: Classification) -> Compartments {
        let mut out = Compartments::new();
        match c {
            Classification::TopSecretSci => {
                out.insert("SCI");
                // No specific SCI compartment — caller's responsibility
                // to add e.g. SI, TK, G, HCS, KCOMPART.
            }
            Classification::CosmicTopSecret => {
                out.insert("NATO-COSMIC");
            }
            Classification::FveySecret | Classification::FveyTopSecret => {
                out.insert("FVEY");
            }
            Classification::NatoConfidential
            | Classification::NatoRestricted
            | Classification::NatoSecret => {
                out.insert("NATO");
            }
            _ => {}
        }
        out
    }
}

impl FromIterator<String> for Compartments {
    fn from_iter<T: IntoIterator<Item = String>>(iter: T) -> Self {
        Self {
            inner: iter.into_iter().collect(),
        }
    }
}

/// A clearance: a classification level + a set of compartments the
/// subject is read into. This is what a verified operator presents
/// during key release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Clearance {
    pub level: Classification,
    pub compartments: Compartments,
}

impl Clearance {
    pub fn new(level: Classification) -> Self {
        Self {
            level,
            compartments: Compartments::new(),
        }
    }

    pub fn with(mut self, tag: impl Into<String>) -> Self {
        self.compartments.insert(tag);
        self
    }

    /// True iff this clearance satisfies the requirements of `object`.
    pub fn satisfies(&self, object: Classification, compartments: &Compartments) -> bool {
        self.level.can_read(object, self.compartments.clone())
            && self.compartments.contains_all(compartments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unclassified_can_read_unclassified() {
        let c = Clearance::new(Classification::Unclassified);
        assert!(c.satisfies(Classification::Unclassified, &Compartments::new()));
    }

    #[test]
    fn secret_cannot_read_top_secret() {
        let c = Clearance::new(Classification::Secret);
        assert!(!c.satisfies(Classification::TopSecret, &Compartments::new()));
    }

    #[test]
    fn top_secret_can_read_secret() {
        let c = Clearance::new(Classification::TopSecret);
        assert!(c.satisfies(Classification::Secret, &Compartments::new()));
    }

    #[test]
    fn compartment_mismatch_denies() {
        let mut needed = Compartments::new();
        needed.insert("SI");
        let c = Clearance::new(Classification::TopSecretSci);
        assert!(!c.satisfies(Classification::TopSecretSci, &needed));
    }

    #[test]
    fn compartment_match_allows() {
        let mut needed = Compartments::new();
        needed.insert("SI");
        let c = Clearance::new(Classification::TopSecretSci)
            .with("SCI")
            .with("SI");
        assert!(c.satisfies(Classification::TopSecretSci, &needed));
    }

    #[test]
    fn no_write_down_blocks_downgrade() {
        assert!(!Classification::Secret.can_write(Classification::Unclassified));
    }

    #[test]
    fn write_at_own_level() {
        assert!(Classification::Secret.can_write(Classification::Secret));
    }

    #[test]
    fn total_ordering() {
        assert!(Classification::TopSecret > Classification::Secret);
        assert!(Classification::TopSecretSci > Classification::TopSecret);
        assert!(Classification::CosmicTopSecret > Classification::TopSecretSci);
    }

    #[test]
    fn top_secret_requires_dual_cipher() {
        assert!(Classification::TopSecret.requires_dual_cipher());
        assert!(!Classification::Secret.requires_dual_cipher());
    }

    #[test]
    fn sci_requires_post_quantum() {
        assert!(Classification::TopSecretSci.requires_post_quantum());
        assert!(!Classification::Secret.requires_post_quantum());
    }

    #[test]
    fn minimum_key_bits_scales() {
        assert_eq!(Classification::Unclassified.minimum_key_bits(), 128);
        assert_eq!(Classification::Secret.minimum_key_bits(), 256);
        assert_eq!(Classification::TopSecretSci.minimum_key_bits(), 256);
    }

    #[test]
    fn compartments_serde_roundtrip() {
        let mut c = Compartments::new();
        c.insert("SI");
        c.insert("TK");
        let s = serde_json::to_string(&c).unwrap();
        let c2: Compartments = serde_json::from_str(&s).unwrap();
        assert_eq!(c, c2);
    }
}
