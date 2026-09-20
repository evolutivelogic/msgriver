use super::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"msgriver/active-state-pointer/v1";

fn key() -> JournalIntegrityKey {
    JournalIntegrityKey(Zeroizing::new([0x41; 32]))
}

fn pointer(origin: PointerOrigin, transition: &str, lineage: &str) -> ActiveStatePointer {
    ActiveStatePointer {
        protocol_version: 7,
        transition_id: transition.to_owned(),
        final_generation: 9,
        lineage_id: lineage.to_owned(),
        target_history_epoch: [0x22; 32],
        origin,
        database_certificate_digest: [0x33; 32],
    }
}

fn expected(pointer: &ActiveStatePointer) -> Vec<u8> {
    let origin = match pointer.origin {
        PointerOrigin::Bootstrap => 1,
        PointerOrigin::Restore => 2,
        PointerOrigin::Rollback => 3,
    };
    let mut wire = vec![1];
    wire.extend_from_slice(&pointer.protocol_version.to_be_bytes());
    wire.extend_from_slice(&(pointer.transition_id.len() as u16).to_be_bytes());
    wire.extend_from_slice(pointer.transition_id.as_bytes());
    wire.extend_from_slice(&pointer.final_generation.to_be_bytes());
    wire.extend_from_slice(&(pointer.lineage_id.len() as u16).to_be_bytes());
    wire.extend_from_slice(pointer.lineage_id.as_bytes());
    wire.extend_from_slice(&pointer.target_history_epoch);
    wire.push(origin);
    wire.extend_from_slice(&pointer.database_certificate_digest);
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x41; 32]).expect("fixed test key");
    mac.update(DOMAIN);
    mac.update(&wire);
    wire.extend_from_slice(&mac.finalize().into_bytes());
    wire
}

fn encode(value: &ActiveStatePointer) -> Vec<u8> {
    match encode_active_state_pointer(&key(), value) {
        Ok(wire) => wire,
        Err(ActiveStatePointerError::MissingActiveStatePointer) => {
            panic!("MissingActiveStatePointer: active_state_pointer")
        }
        Err(error) => panic!("canonical pointer rejected: {error:?}"),
    }
}

fn decode(wire: &[u8]) -> ActiveStatePointer {
    match decode_active_state_pointer(&key(), wire) {
        Ok(value) => value,
        Err(ActiveStatePointerError::MissingActiveStatePointer) => {
            panic!("MissingActiveStatePointer: active_state_pointer")
        }
        Err(error) => panic!("canonical pointer rejected: {error:?}"),
    }
}

fn reject(wire: &[u8]) {
    match decode_active_state_pointer(&key(), wire) {
        Ok(_) => panic!("invalid pointer decoded"),
        Err(error) => {
            if error == ActiveStatePointerError::MissingActiveStatePointer {
                panic!("MissingActiveStatePointer: active_state_pointer")
            }
        }
    }
}

fn resign(wire: &mut [u8]) {
    let tag_start = wire.len() - 32;
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x41; 32]).expect("fixed test key");
    mac.update(DOMAIN);
    mac.update(&wire[..tag_start]);
    wire[tag_start..].copy_from_slice(&mac.finalize().into_bytes());
}

#[test]
fn canonical_hmac_vectors_round_trip_each_origin() {
    for value in [
        pointer(PointerOrigin::Bootstrap, "b", "l"),
        pointer(PointerOrigin::Restore, "restore-7", "lineage-17"),
        pointer(PointerOrigin::Rollback, "rollback", "lineage"),
    ] {
        let wire = expected(&value);
        assert_eq!(
            wire.len(),
            114 + value.transition_id.len() + value.lineage_id.len()
        );
        assert_eq!(encode(&value), wire);
        assert_eq!(decode(&wire), value);
    }
}

#[test]
fn malformed_authentication_and_structure_fail_closed() {
    let value = pointer(PointerOrigin::Restore, "transition", "lineage");
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
    assert!(
        decode_active_state_pointer(&JournalIntegrityKey(Zeroizing::new([0x42; 32])), &wire)
            .is_err()
    );
    for mutation in [(0, 2), (6, 11), (6, 0), (5, 1), (6, 0)] {
        let mut invalid = wire.clone();
        invalid[mutation.0] = mutation.1;
        reject(&invalid);
    }
    let transition_len = value.transition_id.len();
    let generation_start = 7 + transition_len;
    let lineage_length_start = generation_start + 8;
    let mut zero_generation = wire.clone();
    zero_generation[generation_start..generation_start + 8].fill(0);
    reject(&zero_generation);
    let mut zero_digest = wire.clone();
    let digest_start = lineage_length_start + 2 + value.lineage_id.len() + 32 + 1;
    zero_digest[digest_start..digest_start + 32].fill(0);
    reject(&zero_digest);
    let mut unknown_origin = wire;
    unknown_origin[digest_start - 1] = 4;
    reject(&unknown_origin);
}

#[test]
fn staged_lengths_and_authenticated_identifier_errors_fail_closed() {
    let value = pointer(PointerOrigin::Restore, "transition", "lineage");
    let wire = expected(&value);
    for length in 0..7 {
        reject(&wire[..length]);
    }
    let transition_len = value.transition_id.len();
    let lineage_length_start = 15 + transition_len;
    let mut l1_zero = wire.clone();
    l1_zero[5..7].copy_from_slice(&0u16.to_be_bytes());
    resign(&mut l1_zero);
    reject(&l1_zero);
    let mut l1_over = wire.clone();
    l1_over[5..7].copy_from_slice(&256u16.to_be_bytes());
    resign(&mut l1_over);
    reject(&l1_over);
    let mut intermediate = wire.clone();
    intermediate.truncate(16 + transition_len);
    reject(&intermediate);
    let mut l2_zero = wire.clone();
    l2_zero[lineage_length_start..lineage_length_start + 2].copy_from_slice(&0u16.to_be_bytes());
    resign(&mut l2_zero);
    reject(&l2_zero);
    let mut l2_over = wire.clone();
    l2_over[lineage_length_start..lineage_length_start + 2].copy_from_slice(&256u16.to_be_bytes());
    resign(&mut l2_over);
    reject(&l2_over);
    let mut invalid_utf8 = wire.clone();
    invalid_utf8[7] = 0xFF;
    resign(&mut invalid_utf8);
    reject(&invalid_utf8);
    let mut nul_id = wire.clone();
    nul_id[7] = 0;
    resign(&mut nul_id);
    reject(&nul_id);
    let mut invalid_utf8_bad_tag = invalid_utf8;
    *invalid_utf8_bad_tag.last_mut().expect("tag") ^= 1;
    reject(&invalid_utf8_bad_tag);
}

#[test]
fn boundary_is_private_and_has_no_publication_capability() {
    let source = include_str!("active_state_pointer.rs");
    for forbidden in [
        "pub fn encode_active_state_pointer",
        "std::fs",
        "rename",
        "sqlite",
        "O_EXCL",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
    assert!(source.contains("FRONTIER: active_state_pointer"));
}
