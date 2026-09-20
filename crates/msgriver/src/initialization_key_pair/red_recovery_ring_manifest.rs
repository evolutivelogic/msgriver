use super::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"msgriver/recovery-ring/v1";
const TAG_BYTES: usize = 32;

fn key(byte: u8) -> JournalIntegrityKey {
    JournalIntegrityKey(Zeroizing::new([byte; 32]))
}

fn entry(generation: u64, phase: RecoveryRingPhase) -> RecoveryRingEntry {
    RecoveryRingEntry {
        generation: RecoveryGeneration(generation),
        phase,
    }
}

fn manifest(entries: Vec<RecoveryRingEntry>) -> RecoveryRingManifest {
    RecoveryRingManifest { entries }
}

fn phase_code(phase: RecoveryRingPhase) -> u8 {
    match phase {
        RecoveryRingPhase::Retained => 1,
        RecoveryRingPhase::Active => 2,
        RecoveryRingPhase::PendingEscrow => 3,
    }
}

fn expected(value: &RecoveryRingManifest) -> Vec<u8> {
    assert!(value.entries.len() <= 16, "test vector capacity");
    let mut wire = vec![1, value.entries.len() as u8];
    for entry in &value.entries {
        wire.extend_from_slice(&entry.generation.0.to_be_bytes());
        wire.push(phase_code(entry.phase));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x41; 32]).expect("fixed test key");
    mac.update(DOMAIN);
    mac.update(&wire);
    wire.extend_from_slice(&mac.finalize().into_bytes());
    wire
}

fn encode(value: &RecoveryRingManifest) -> Vec<u8> {
    match encode_recovery_ring_manifest(&key(0x41), value) {
        Ok(wire) => wire,
        Err(RecoveryRingManifestError::MissingRecoveryRingManifest) => {
            panic!("MissingRecoveryRingManifest: recovery_ring_manifest")
        }
        Err(error) => panic!("canonical recovery ring rejected: {error:?}"),
    }
}

fn decode(wire: &[u8]) -> RecoveryRingManifest {
    match decode_recovery_ring_manifest(&key(0x41), wire) {
        Ok(value) => value,
        Err(RecoveryRingManifestError::MissingRecoveryRingManifest) => {
            panic!("MissingRecoveryRingManifest: recovery_ring_manifest")
        }
        Err(error) => panic!("canonical recovery ring rejected: {error:?}"),
    }
}

fn reject(wire: &[u8]) {
    match decode_recovery_ring_manifest(&key(0x41), wire) {
        Ok(_) => panic!("invalid recovery ring decoded"),
        Err(RecoveryRingManifestError::MissingRecoveryRingManifest) => {
            panic!("MissingRecoveryRingManifest: recovery_ring_manifest")
        }
        Err(RecoveryRingManifestError::InvalidRecoveryRingManifest) => {}
    }
}

fn resign(wire: &mut [u8]) {
    let tag_start = wire.len() - TAG_BYTES;
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x41; 32]).expect("fixed test key");
    mac.update(DOMAIN);
    mac.update(&wire[..tag_start]);
    wire[tag_start..].copy_from_slice(&mac.finalize().into_bytes());
}

#[test]
fn canonical_hmac_vectors_round_trip_empty_mixed_and_capacity() {
    let empty = manifest(vec![]);
    let mixed = manifest(vec![
        entry(1, RecoveryRingPhase::Retained),
        entry(4, RecoveryRingPhase::Active),
        entry(8, RecoveryRingPhase::PendingEscrow),
    ]);
    let capacity = manifest(
        (1..=16)
            .map(|generation| {
                entry(
                    generation,
                    match generation {
                        8 => RecoveryRingPhase::Active,
                        16 => RecoveryRingPhase::PendingEscrow,
                        _ => RecoveryRingPhase::Retained,
                    },
                )
            })
            .collect(),
    );

    for value in [&empty, &mixed, &capacity] {
        let wire = expected(value);
        assert_eq!(wire.len(), 34 + 9 * value.entries.len());
        assert_eq!(encode(value), wire, "independent HMAC vector");
        assert_eq!(decode(&wire), value.clone());
    }
}

#[test]
fn structural_and_authentication_failures_are_closed() {
    let value = manifest(vec![
        entry(1, RecoveryRingPhase::Retained),
        entry(4, RecoveryRingPhase::Active),
        entry(8, RecoveryRingPhase::PendingEscrow),
    ]);
    let wire = expected(&value);
    for length in 0..wire.len() {
        reject(&wire[..length]);
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    reject(&trailing);
    let mut bad_tag = wire.clone();
    *bad_tag.last_mut().expect("tag") ^= 1;
    reject(&bad_tag);
    reject(&[1, 17]);

    let singleton = expected(&manifest(vec![entry(1, RecoveryRingPhase::Retained)]));
    let mut count_zero_with_entry = singleton.clone();
    count_zero_with_entry[1] = 0;
    resign(&mut count_zero_with_entry);
    reject(&count_zero_with_entry);
    let mut count_two_with_one_entry = singleton;
    count_two_with_one_entry[1] = 2;
    resign(&mut count_two_with_one_entry);
    reject(&count_two_with_one_entry);
    assert!(decode_recovery_ring_manifest(&key(0x42), &wire).is_err());
}

#[test]
fn authenticated_semantic_failures_are_closed() {
    let two_entries = manifest(vec![
        entry(4, RecoveryRingPhase::Retained),
        entry(8, RecoveryRingPhase::Active),
    ]);
    let wire = expected(&two_entries);

    for (offset, byte) in [(0, 2), (10, 0), (10, 4)] {
        let mut invalid = wire.clone();
        invalid[offset] = byte;
        resign(&mut invalid);
        reject(&invalid);
    }
    for second_generation in [0_u64, 4, 3] {
        let mut invalid = wire.clone();
        invalid[11..19].copy_from_slice(&second_generation.to_be_bytes());
        resign(&mut invalid);
        reject(&invalid);
    }
    for phase in [RecoveryRingPhase::Active, RecoveryRingPhase::PendingEscrow] {
        let mut invalid = expected(&manifest(vec![entry(4, phase), entry(8, phase)]));
        resign(&mut invalid);
        reject(&invalid);
    }
}

#[test]
fn boundary_is_private_and_has_no_io_or_authority_capability() {
    let source = include_str!("recovery_ring_manifest.rs");
    for forbidden in [
        "pub struct RecoveryRingManifest",
        "pub fn encode_recovery_ring_manifest",
        "std::fs",
        "rustix::fs",
        "journal",
        "checkpoint",
        "rename",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
    assert!(source.contains("FRONTIER: recovery_ring_manifest"));
}
