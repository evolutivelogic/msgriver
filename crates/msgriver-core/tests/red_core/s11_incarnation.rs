use super::harness::{CompareResult, Oracle, TestCaseError, case, hex};
use msgriver_core::generation::{
    BranchSerial, JournalNamespaceProvider, OwnerNamespace, compose_incarnation,
    decode_incarnation_hex, derive_owner_namespace, encode_incarnation_hex, next_branch_serial,
};
use msgriver_core::incarnation::{
    AllocatorWitness, LocalWitnessKind, OperationId, TargetValidation, TargetWitnessSet,
    TransitionClass, WitnessClassification, WitnessSource, classify_transition, classify_witness,
    derive_nonreused_serial, validate_target,
};
use msgriver_core::{Frontier, RejectClass};

const LABEL: &[u8] = b"msgriver/resource-incarnation-namespace/v1";
const KEY_A: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const KEY_B: [u8; 32] = [0xff; 32];
const NAMESPACE_A: [u8; 24] = [
    0x1c, 0x49, 0x79, 0x8d, 0xe4, 0xfd, 0xd8, 0x48, 0x71, 0x4c, 0x7d, 0xc6, 0x10, 0x35, 0x0e, 0xbb,
    0x66, 0xae, 0x5e, 0xe8, 0x15, 0x27, 0x5f, 0xbe,
];

struct FixedJournalProvider([u8; 32]);

impl JournalNamespaceProvider for FixedJournalProvider {
    fn derive_resource_incarnation_namespace_v1(&self) -> [u8; 24] {
        let mut block = [0u8; 64];
        block[..self.0.len()].copy_from_slice(&self.0);
        let mut inner = Vec::with_capacity(64 + LABEL.len());
        for byte in block {
            inner.push(byte ^ 0x36);
        }
        inner.extend_from_slice(LABEL);
        let inner_hash = super::harness::sha256(&inner);
        let mut outer = Vec::with_capacity(64 + inner_hash.len());
        for byte in block {
            outer.push(byte ^ 0x5c);
        }
        outer.extend_from_slice(&inner_hash);
        let digest = super::harness::sha256(&outer);
        let mut namespace = [0u8; 24];
        namespace.copy_from_slice(&digest[..24]);
        namespace
    }
}

fn namespace_a(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let actual = derive_owner_namespace(&FixedJournalProvider(KEY_A)).as_bytes();
    if oracle.expect_is("ok")
        && actual == NAMESPACE_A
        && hex(&actual) == oracle.req("expect_namespace_hex")?
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "namespace derivation vector mismatch".into(),
        ))
    }
}

fn crosshost(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let first = derive_owner_namespace(&FixedJournalProvider(KEY_A)).as_bytes();
    let second = derive_owner_namespace(&FixedJournalProvider(KEY_B)).as_bytes();
    if oracle.expect_is("ok") && first != second && oracle.bool("expect_distinct")? {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "cross-host namespaces are not distinct".into(),
        ))
    }
}

fn incarnation() -> Result<msgriver_core::generation::ResourceIncarnation, TestCaseError> {
    let serial = BranchSerial::new(0x1122_3344_5566_7788)
        .map_err(|_| TestCaseError::Parse("test serial rejected".into()))?;
    Ok(compose_incarnation(
        OwnerNamespace::from_bytes([0xaa; 24]),
        serial,
    ))
}

fn compose(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let value = incarnation()?;
    match BranchSerial::new(0) {
        Err(error) if error.reject_class() == Some(RejectClass::IncarnationSerialZero) => {}
        _ => {
            return Ok(CompareResult::Mismatch(
                "zero branch serial accepted".into(),
            ));
        }
    }
    if oracle.expect_is("ok") && encode_incarnation_hex(value) == oracle.req("expect_hex")? {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "incarnation composition mismatch".into(),
        ))
    }
}

fn encode_hex(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let value = incarnation()?;
    let wire = encode_incarnation_hex(value);
    match decode_incarnation_hex(&wire) {
        Ok(decoded) if decoded == value && wire.len() == oracle.u64("expect_width")? as usize => {
            Ok(CompareResult::Pass)
        }
        _ => Ok(CompareResult::Mismatch(
            "incarnation hex round-trip mismatch".into(),
        )),
    }
}

fn decode_hex(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let value = incarnation()?;
    let wire = encode_incarnation_hex(value);
    let rows = [
        ("00".to_owned(), RejectClass::IncarnationHexWidth),
        (wire.to_ascii_uppercase(), RejectClass::IncarnationHexCase),
        (
            format!("z{}", &wire[1..]),
            RejectClass::IncarnationHexCharacter,
        ),
    ];
    for (input, expected) in rows {
        match decode_incarnation_hex(&input) {
            Err(error) if error.reject_class() == Some(expected) => {}
            _ => {
                return Ok(CompareResult::Mismatch(
                    "wrong incarnation hex rejection".into(),
                ));
            }
        }
    }
    if oracle.expect_is("ok") && oracle.list("expect_rejections")?.len() == 3 {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("decode oracle mismatch".into()))
    }
}

fn next_serial(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    for (high_water, expected) in [
        (0, 1),
        (0x0000_0000_ffff_ffff, 0x0000_0001_0000_0000),
        (u64::MAX - 1, u64::MAX),
    ] {
        match next_branch_serial(high_water) {
            Ok(serial) if serial.get() == expected => {}
            _ => {
                return Ok(CompareResult::Mismatch(
                    "branch serial carry mismatch".into(),
                ));
            }
        }
    }
    match next_branch_serial(u64::MAX) {
        Err(error) if error.reject_class() == Some(RejectClass::IncarnationExhausted) => {}
        _ => {
            return Ok(CompareResult::Mismatch(
                "branch serial exhaustion mismatch".into(),
            ));
        }
    }
    if oracle.expect_is("ok") && oracle.req("expect_exhaustion")? == "incarnation_exhausted" {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("serial oracle mismatch".into()))
    }
}

const ALLOCATING: [OperationId; 3] = [
    OperationId::BootstrapCreate,
    OperationId::RestoreCreate,
    OperationId::UpgradeRollback,
];
const CONTINUATIONS: [OperationId; 6] = [
    OperationId::ConfigurationActivate,
    OperationId::StateKeyRotate,
    OperationId::StateKeyRetire,
    OperationId::UpgradeMigrate,
    OperationId::UpgradeActivate,
    OperationId::ForwardRepair,
];
const LOCAL_KINDS: [LocalWitnessKind; 5] = [
    LocalWitnessKind::SelectedPointer,
    LocalWitnessKind::CurrentGuardedResource,
    LocalWitnessKind::AllocatingIntentTarget,
    LocalWitnessKind::LocallyStagedTarget,
    LocalWitnessKind::HistoryOrProvenanceEpoch,
];

fn classification(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    if !ALLOCATING
        .into_iter()
        .all(|operation| classify_transition(operation) == TransitionClass::Allocating)
        || !CONTINUATIONS
            .into_iter()
            .all(|operation| classify_transition(operation) == TransitionClass::Continuation)
        || classify_transition(OperationId::Other) != TransitionClass::NonAllocator
    {
        return Ok(CompareResult::Mismatch(
            "operation classification mismatch".into(),
        ));
    }
    if oracle.expect_is("ok") && oracle.u64("expect_allocating_count")? == 3 {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("operation oracle mismatch".into()))
    }
}

fn local_witness(kind: LocalWitnessKind) -> AllocatorWitness {
    AllocatorWitness {
        source: WitnessSource::Local(kind),
        namespace: OwnerNamespace::from_bytes([0x44; 24]),
        serial: 4,
    }
}

fn witness_matrix(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let root = OwnerNamespace::from_bytes([0x44; 24]);
    for kind in LOCAL_KINDS {
        if classify_witness(local_witness(kind), root, 4) != WitnessClassification::LocalWitness {
            return Ok(CompareResult::Mismatch("local witness rejected".into()));
        }
    }
    if oracle.expect_is("ok") && oracle.u64("expect_local_kinds")? == LOCAL_KINDS.len() as u64 {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("witness oracle mismatch".into()))
    }
}

fn target_matrix(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let rows = [
        (
            TargetWitnessSet {
                collision: false,
                source_matches: true,
                target_serial_matches: true,
            },
            TargetValidation::Ok,
        ),
        (
            TargetWitnessSet {
                collision: true,
                source_matches: true,
                target_serial_matches: true,
            },
            TargetValidation::Collision,
        ),
        (
            TargetWitnessSet {
                collision: false,
                source_matches: false,
                target_serial_matches: true,
            },
            TargetValidation::SourceMismatch,
        ),
        (
            TargetWitnessSet {
                collision: false,
                source_matches: true,
                target_serial_matches: false,
            },
            TargetValidation::TargetSerialMismatch,
        ),
    ];
    for (input, expected) in rows {
        if validate_target(input) != expected || validate_target(input) != expected {
            return Ok(CompareResult::Mismatch("target validation mismatch".into()));
        }
    }
    if oracle.expect_is("ok") && oracle.list("expect_outcomes")?.len() == 4 {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("target oracle mismatch".into()))
    }
}

fn nonreuse(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    match (derive_nonreused_serial(41), derive_nonreused_serial(41)) {
        (Ok(first), Ok(second))
            if first == second && first.get() == oracle.u64("expect_serial")? =>
        {
            Ok(CompareResult::Pass)
        }
        _ => Ok(CompareResult::Mismatch(
            "same-root non-reuse mismatch".into(),
        )),
    }
}

fn foreign_epochs(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let root = OwnerNamespace::from_bytes([0x44; 24]);
    let foreign = AllocatorWitness {
        source: WitnessSource::ForeignAuthenticatedAncestry,
        namespace: OwnerNamespace::from_bytes([0x55; 24]),
        serial: u64::MAX,
    };
    let imported = AllocatorWitness {
        source: WitnessSource::ImportedKeyOrigin,
        ..foreign
    };
    if classify_witness(foreign, root, 4) == WitnessClassification::ForeignAncestry
        && classify_witness(imported, root, 4) == WitnessClassification::ForeignAncestry
        && oracle.expect_is("ok")
        && oracle.req("expect_class")? == "foreign_ancestry"
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "foreign witness classification mismatch".into(),
        ))
    }
}

fn witness_reject(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let root = OwnerNamespace::from_bytes([0x44; 24]);
    let wrong_namespace = AllocatorWitness {
        namespace: OwnerNamespace::from_bytes([0x45; 24]),
        ..local_witness(LocalWitnessKind::SelectedPointer)
    };
    let above_high_water = AllocatorWitness {
        serial: 5,
        ..local_witness(LocalWitnessKind::CurrentGuardedResource)
    };
    if classify_witness(wrong_namespace, root, 4) == WitnessClassification::Corrupt
        && classify_witness(above_high_water, root, 4) == WitnessClassification::Corrupt
        && oracle.expect_is("ok")
        && oracle.req("expect_class")? == "corrupt"
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch("defect witness accepted".into()))
    }
}

fn witness_kinds(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    let root = OwnerNamespace::from_bytes([0x44; 24]);
    let unknown = AllocatorWitness {
        source: WitnessSource::Unknown,
        ..local_witness(LocalWitnessKind::SelectedPointer)
    };
    if LOCAL_KINDS.into_iter().all(|kind| {
        classify_witness(local_witness(kind), root, 4) == WitnessClassification::LocalWitness
    }) && classify_witness(unknown, root, 4) == WitnessClassification::Corrupt
        && oracle.expect_is("ok")
        && oracle.u64("expect_accepted_kinds")? == LOCAL_KINDS.len() as u64
    {
        Ok(CompareResult::Pass)
    } else {
        Ok(CompareResult::Mismatch(
            "witness kind registry mismatch".into(),
        ))
    }
}

#[test]
fn core_s11_incarn_derive_namespace() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-DERIVE-NAMESPACE",
        "tests/fixtures/oracles/core/core-s11-incarn-derive-namespace.txt",
        "55abcdede2e8bb2235ffc1b53ed407d76803c0b3c358cedb465c5771ed7beb26",
        Frontier::MacDomainSeparate,
        namespace_a,
    )
}

#[test]
fn core_s11_incarn_namespace_vector() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-NAMESPACE-VECTOR",
        "tests/fixtures/oracles/core/core-s11-incarn-namespace-vector.txt",
        "3484f3072f0304b5b4faf9bfe031a21261d93a067ce24d5a6c6b6e73457d5f89",
        Frontier::MacDomainSeparate,
        namespace_a,
    )
}

#[test]
fn core_s11_incarn_crosshost_disjoint() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-CROSSHOST-DISJOINT",
        "tests/fixtures/oracles/core/core-s11-incarn-crosshost-disjoint.txt",
        "32cee8b023496e7add17d4595794705a9b381ca85fa98b4fcf0a1dc5c0a05d50",
        Frontier::MacDomainSeparate,
        crosshost,
    )
}

#[test]
fn core_s11_incarn_compose() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-COMPOSE",
        "tests/fixtures/oracles/core/core-s11-incarn-compose.txt",
        "6672aec982ef5a92d8365dd7759ea334e172e5a8595cfe9a2dfea7cd43b9667c",
        Frontier::IncarnationAlloc,
        compose,
    )
}

#[test]
fn core_s11_incarn_encode_hex() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-ENCODE-HEX",
        "tests/fixtures/oracles/core/core-s11-incarn-encode-hex.txt",
        "bd8d79a4eb0de87a56dd1158e2fede0040f8b1cdba85154245f142f047d2f93d",
        Frontier::IncarnationAlloc,
        encode_hex,
    )
}

#[test]
fn core_s11_incarn_decode_hex() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-DECODE-HEX",
        "tests/fixtures/oracles/core/core-s11-incarn-decode-hex.txt",
        "3105ee62c71dc853c32de30f2b0f62c57117326b804f22e53a1b2f6b7e7dc3b6",
        Frontier::IncarnationAlloc,
        decode_hex,
    )
}

#[test]
fn core_s11_incarn_next_serial() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-NEXT-SERIAL",
        "tests/fixtures/oracles/core/core-s11-incarn-next-serial.txt",
        "7b7e07219f00d66cbe83093f10c38f3e9f9f3530003ddbd7aa5cddc976dfd4b1",
        Frontier::IncarnationAlloc,
        next_serial,
    )
}

#[test]
fn core_s11_incarn_classify_transition() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-CLASSIFY-TRANSITION",
        "tests/fixtures/oracles/core/core-s11-incarn-classify-transition.txt",
        "c2d7deb7052fea787e0e045fa1ae9befa904b9d7441ddddfb08525dbdd4ab60a",
        Frontier::IncarnationAlloc,
        classification,
    )
}

#[test]
fn core_s11_incarn_classify_witness() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-CLASSIFY-WITNESS",
        "tests/fixtures/oracles/core/core-s11-incarn-classify-witness.txt",
        "75467d5ee33cc09af55f0c095b6b7413566cd0968bfef9e4824ad332f4eaa258",
        Frontier::IncarnationAlloc,
        witness_matrix,
    )
}

#[test]
fn core_s11_incarn_validate_target() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-VALIDATE-TARGET",
        "tests/fixtures/oracles/core/core-s11-incarn-validate-target.txt",
        "65c5091890d51976709e9e285a088ebc17c476cebcb815402d33e658740626c5",
        Frontier::IncarnationAlloc,
        target_matrix,
    )
}

#[test]
fn core_s11_incarn_nonreuse_highwater() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-NONREUSE-HIGHWATER",
        "tests/fixtures/oracles/core/core-s11-incarn-nonreuse-highwater.txt",
        "cae52d13d239665efcd5598d867b743ea10201f6efdae6b03d38a1f8551ba675",
        Frontier::IncarnationAlloc,
        nonreuse,
    )
}

#[test]
fn core_s11_incarn_allocating_ops() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-ALLOCATING-OPS",
        "tests/fixtures/oracles/core/core-s11-incarn-allocating-ops.txt",
        "5cdcb8376df547691cd6565c43e06ef995ca1679c0aef91e27469614d18a227a",
        Frontier::IncarnationAlloc,
        classification,
    )
}

#[test]
fn core_s11_incarn_foreign_epochs() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-FOREIGN-EPOCHS",
        "tests/fixtures/oracles/core/core-s11-incarn-foreign-epochs.txt",
        "d460f64137fd1c66ed14a66f9b4b06319a82780f5570982e44ccb0b9bf81a448",
        Frontier::IncarnationAlloc,
        foreign_epochs,
    )
}

#[test]
fn core_s11_incarn_witness_reject() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-WITNESS-REJECT",
        "tests/fixtures/oracles/core/core-s11-incarn-witness-reject.txt",
        "f8f356f6a836f98be5b74aac2aba4605a55f9739cc050ea7c140c8bf9194e146",
        Frontier::IncarnationAlloc,
        witness_reject,
    )
}

#[test]
fn core_s11_incarn_witness_kinds() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-INCARN-WITNESS-KINDS",
        "tests/fixtures/oracles/core/core-s11-incarn-witness-kinds.txt",
        "c27361e788bda7cf83fdebf3af64f582248f43d77f99840683808b615fb982bd",
        Frontier::IncarnationAlloc,
        witness_kinds,
    )
}
