//! RED contract for the literal operation-04 profile body.

use super::*;

fn digest(value: u8) -> [u8; 32] {
    [value; 32]
}

#[test]
fn profile_body_has_only_the_three_canonical_lengths_and_round_trips() {
    let forms = [
        RecoveryKeyGenerateProfile {
            variant: RecoveryKeyGenerateVariant::Generate,
            issuance_digest: None,
            confirmation_digest: None,
        },
        RecoveryKeyGenerateProfile {
            variant: RecoveryKeyGenerateVariant::Generate,
            issuance_digest: Some(digest(0x71)),
            confirmation_digest: None,
        },
        RecoveryKeyGenerateProfile {
            variant: RecoveryKeyGenerateVariant::Acknowledge,
            issuance_digest: None,
            confirmation_digest: Some(digest(0x72)),
        },
        RecoveryKeyGenerateProfile {
            variant: RecoveryKeyGenerateVariant::Acknowledge,
            issuance_digest: Some(digest(0x71)),
            confirmation_digest: Some(digest(0x72)),
        },
    ];
    for profile in forms {
        let wire = encode_recovery_key_generate_profile(profile);
        assert!(matches!(wire.len(), 3 | 36 | 69));
        assert_eq!(decode_recovery_key_generate_profile(&wire), Ok(profile));
    }
}

#[test]
fn decoder_rejects_noncanonical_format_variant_count_kind_order_and_trailing_bytes() {
    let mut issuance = vec![1, 1, 1, 1];
    issuance.extend_from_slice(&digest(0x71));
    let mut duplicate = vec![1, 1, 2, 1];
    duplicate.extend_from_slice(&digest(0x71));
    duplicate.push(1);
    duplicate.extend_from_slice(&digest(0x72));
    let mut descending = vec![1, 1, 2, 2];
    descending.extend_from_slice(&digest(0x72));
    descending.push(1);
    descending.extend_from_slice(&digest(0x71));
    let mut unknown_kind = vec![1, 1, 1, 3];
    unknown_kind.extend_from_slice(&digest(0x71));
    let mut trailing = issuance.clone();
    trailing.push(0);
    for wire in [
        vec![],
        vec![1, 1],
        vec![2, 1, 0],
        vec![1, 3, 0],
        vec![1, 1, 3],
        vec![1, 1, 1],
        duplicate,
        descending,
        unknown_kind,
        trailing,
    ] {
        assert_eq!(
            decode_recovery_key_generate_profile(&wire),
            Err(RecoveryKeyGenerateProfileError::InvalidProfile)
        );
    }
}
