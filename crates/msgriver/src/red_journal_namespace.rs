//! Frozen Task 0013 unit contract inside the private journal-key boundary.
//!
//! Synthetic journal-key bytes are used only by this child module. Production
//! callers can receive the fixed-width namespace capability solely through
//! `JournalNamespaceProvider`; they cannot inspect a journal key or request a
//! generic MAC.

use super::*;
use std::mem::size_of;
use zeroize::Zeroizing;

const JOURNAL_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const EXPECTED_NAMESPACE: [u8; 24] = [
    0x1c, 0x49, 0x79, 0x8d, 0xe4, 0xfd, 0xd8, 0x48, 0x71, 0x4c, 0x7d, 0xc6, 0x10, 0x35, 0x0e, 0xbb,
    0x66, 0xae, 0x5e, 0xe8, 0x15, 0x27, 0x5f, 0xbe,
];

fn journal_key(bytes: [u8; 32]) -> JournalIntegrityKey {
    JournalIntegrityKey(Zeroizing::new(bytes))
}

fn require_namespace(key: &JournalIntegrityKey) -> Result<[u8; 24], String> {
    match key.derive_resource_incarnation_namespace_v1() {
        Ok(namespace) => Ok(namespace.derive_resource_incarnation_namespace_v1()),
        Err(JournalNamespaceError::MissingDerivation) => {
            Err("JOURNAL-NAMESPACE: missing behavior at `journal_namespace_derivation`".to_owned())
        }
    }
}

#[test]
fn known_answer_uses_the_exact_fixed_label_and_truncation() -> Result<(), String> {
    assert_eq!(
        require_namespace(&journal_key(JOURNAL_KEY))?,
        EXPECTED_NAMESPACE
    );
    Ok(())
}

#[test]
fn derivation_is_deterministic_and_changed_keys_do_not_share_a_namespace() -> Result<(), String> {
    let first = require_namespace(&journal_key(JOURNAL_KEY))?;
    let repeated = require_namespace(&journal_key(JOURNAL_KEY))?;
    let mut changed_key = JOURNAL_KEY;
    changed_key[31] ^= 1;
    let changed = require_namespace(&journal_key(changed_key))?;

    assert_eq!(first, repeated);
    assert_ne!(first, changed);
    Ok(())
}

#[test]
fn missing_derivation_frontier_is_causal_and_static() {
    match journal_key(JOURNAL_KEY).derive_resource_incarnation_namespace_v1() {
        Err(JournalNamespaceError::MissingDerivation) => {
            panic!("MissingDerivation: journal_namespace_derivation")
        }
        Ok(_) => {}
    }
}

#[test]
fn capability_surface_is_fixed_width_private_and_non_general() {
    const SOURCE: &str = include_str!("initialization_key_pair.rs");

    assert_eq!(size_of::<JournalNamespaceCapability>(), 24);
    assert!(!SOURCE.contains("pub struct JournalNamespaceCapability"));
    assert!(!SOURCE.contains("pub fn derive_resource_incarnation_namespace_v1"));
    assert!(!SOURCE.contains("MacKeyId"));
    assert!(!SOURCE.contains("serde"));
    assert!(!SOURCE.contains("std::fs"));
    assert!(!SOURCE.contains("impl fmt::Debug for JournalNamespaceError"));
    assert!(!SOURCE.contains("impl fmt::Display for JournalNamespaceError"));
    assert!(!SOURCE.contains("impl fmt::Debug for JournalNamespaceCapability"));
    assert!(!SOURCE.contains("impl fmt::Display for JournalNamespaceCapability"));
}
