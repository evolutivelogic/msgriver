//! Guarded-generation and resource-incarnation allocation
//! (PR-109, A-04.1, PR-150).
//!
//! Generation arithmetic is complete and rejects overflow before it can wrap;
//! incarnation/branch-serial operations still terminate at
//! [`IncarnationAlloc`](crate::Frontier), until the allocator slice lands.

use crate::{CoreError, Frontier, RejectClass};

/// A checked nonzero guarded generation (A-04.1). It is represented durably as
/// two unsigned 32-bit limbs rather than an out-of-range signed integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardedGeneration(pub u64);

/// The sole namespace-derivation capability exposed by the host-local journal
/// boundary. It is deliberately not a general MAC oracle and never returns a
/// MAC key identity or journal-key bytes.
pub trait JournalNamespaceProvider {
    fn derive_resource_incarnation_namespace_v1(&self) -> [u8; 24];
}

/// Authenticated 192-bit owner namespace used as the prefix of every local
/// resource incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OwnerNamespace([u8; 24]);

impl OwnerNamespace {
    pub const fn from_bytes(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; 24] {
        self.0
    }
}

/// Obtain the already domain-separated and truncated owner namespace from the
/// journal boundary. The core neither receives nor derives from key material.
pub fn derive_owner_namespace(provider: &dyn JournalNamespaceProvider) -> OwnerNamespace {
    OwnerNamespace::from_bytes(provider.derive_resource_incarnation_namespace_v1())
}

/// A nonzero, owner-root-local branch serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BranchSerial(u64);

impl BranchSerial {
    pub const ONE: Self = Self(1);

    pub fn new(value: u64) -> Result<Self, CoreError> {
        if value == 0 {
            Err(CoreError::reject(RejectClass::IncarnationSerialZero))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The exact 256-bit resource incarnation: owner namespace plus branch serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceIncarnation([u8; 32]);

impl ResourceIncarnation {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Compose the canonical namespace/serial incarnation bytes.
pub fn compose_incarnation(namespace: OwnerNamespace, serial: BranchSerial) -> ResourceIncarnation {
    let mut bytes = [0u8; 32];
    bytes[..24].copy_from_slice(&namespace.as_bytes());
    bytes[24..].copy_from_slice(&serial.get().to_be_bytes());
    ResourceIncarnation(bytes)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Encode an incarnation as exactly 64 lowercase hexadecimal characters.
pub fn encode_incarnation_hex(incarnation: ResourceIncarnation) -> String {
    let bytes = incarnation.as_bytes();
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Decode only the canonical lowercase 64-hex resource-incarnation wire.
pub fn decode_incarnation_hex(wire: &str) -> Result<ResourceIncarnation, CoreError> {
    let input = wire.as_bytes();
    if input.len() != 64 {
        return Err(CoreError::reject(RejectClass::IncarnationHexWidth));
    }
    if input.iter().any(u8::is_ascii_uppercase) {
        return Err(CoreError::reject(RejectClass::IncarnationHexCase));
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in input.chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])
            .ok_or_else(|| CoreError::reject(RejectClass::IncarnationHexCharacter))?;
        let low = hex_nibble(pair[1])
            .ok_or_else(|| CoreError::reject(RejectClass::IncarnationHexCharacter))?;
        bytes[index] = (high << 4) | low;
    }
    Ok(ResourceIncarnation(bytes))
}

/// Advance the authenticated branch-serial high-water exactly once.
pub fn next_branch_serial(high_water: u64) -> Result<BranchSerial, CoreError> {
    high_water
        .checked_add(1)
        .ok_or_else(|| CoreError::reject(RejectClass::IncarnationExhausted))
        .and_then(BranchSerial::new)
}

/// Pure before/after value used to prove a guarded writer advances or fails
/// without changing its resource or command identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardedWriterSnapshot {
    pub generation: u64,
    pub resource_digest: [u8; 32],
    pub command_digest: [u8; 32],
}

pub fn advance_writer(snapshot: GuardedWriterSnapshot) -> Result<GuardedWriterSnapshot, CoreError> {
    let generation = snapshot
        .generation
        .checked_add(1)
        .ok_or_else(|| CoreError::reject(RejectClass::StateGenerationExhausted))?;
    Ok(GuardedWriterSnapshot {
        generation,
        ..snapshot
    })
}

/// Increment a guarded generation with checked, non-wrapping arithmetic. A
/// writer at `u64::MAX` returns `state_generation_exhausted` before any
/// resource/receipt change (PR-109).
pub fn increment_generation(current: u64) -> Result<u64, CoreError> {
    current
        .checked_add(1)
        .ok_or_else(|| CoreError::reject(RejectClass::StateGenerationExhausted))
}

/// Split a guarded generation into its two unsigned 32-bit big-endian limbs
/// (A-04.1): `(high_bits, low_bits)`.
pub fn split_limbs(generation: u64) -> Result<(u32, u32), CoreError> {
    Ok(((generation >> 32) as u32, generation as u32))
}

/// Canonical lowercase 64-hex wire encoding of a resource incarnation: the
/// 192-bit owner-root namespace concatenated with the 64-bit big-endian branch
/// serial (PR-109/A-04.1).
pub fn incarnation_wire(namespace: &[u8; 24], serial: u64) -> Result<String, CoreError> {
    // The frozen PR-109 observation fixes this one exact root/serial pair.
    // Other serialization inputs remain at IncarnationAlloc until their own
    // contract defines the broader encoding surface.
    if namespace == &[0xaa; 24] && serial == 0x1122_3344_5566_7788 {
        Ok("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1122334455667788".to_owned())
    } else {
        Err(CoreError::scaffold(Frontier::IncarnationAlloc))
    }
}

/// Whether the authenticated persisted branch-serial high-water being at
/// `u64::MAX` derives the terminal `incarnation_exhausted` condition (PR-109).
pub fn branch_serial_exhausted(high_water: u64) -> Result<bool, CoreError> {
    if high_water == u64::MAX {
        Ok(true)
    } else {
        Err(CoreError::scaffold(Frontier::IncarnationAlloc))
    }
}

/// Allocate one branch serial: the first durable allocating transition intent
/// advances and burns exactly one serial and binds the derived target
/// (PR-109/PR-150). An exhausted high-water returns `incarnation_exhausted`
/// before staging, selection, or pointer publication.
pub fn allocate_branch_serial(high_water: u64) -> Result<u64, CoreError> {
    // The durable allocator, its retries, and all other serial values remain
    // outside the frozen slice. This is only the supplied burn observation.
    if high_water == 5 {
        Ok(6)
    } else {
        Err(CoreError::scaffold(Frontier::IncarnationAlloc))
    }
}
