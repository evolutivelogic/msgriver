//! Unpublished initialization samples, with no persistence or publication capability.
//!
//! Only the two marked Missing bodies may change after the RED freeze. Secret
//! fields remain private, purpose-specific, non-Clone, and zeroizing; tests are
//! children of this module so synthetic bytes need no production export API.

use hmac::{Hmac, Mac};
use msgriver_core::generation::JournalNamespaceProvider;
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroizing;

mod active_state_pointer;
mod active_state_pointer_caller;
#[cfg(test)]
pub(super) mod active_state_pointer_publisher {
    pub(super) use super::active_state_pointer_caller::ActiveStatePointerPublicationMode;
}
mod clock_authority_projection;
mod clock_checkpoint_body;
mod control_journal_header;
mod control_journal_image;
mod control_journal_record;
mod fixed_root_command;
mod fixed_root_command_authenticated;
mod fixed_root_command_record;
mod publication;
mod recovery_key_event;
mod recovery_key_generate_profile;
mod recovery_ring_manifest;
mod state_mac_key_file;

#[allow(unused_imports)]
pub(crate) use state_mac_key_file::{StateMacKeySecret, decode_state_mac_key_file};

#[cfg(test)]
#[path = "initialization_key_pair/red_state_mac_key_reader_bridge.rs"]
mod red_state_mac_key_reader_bridge;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitializationKeyRole {
    JournalIntegrity,
    PortableReservation,
}

/// Adapter errors carry neither diagnostics nor partially acquired material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntropyFailure {
    Failed,
    MissingOsAdapter,
}

impl fmt::Display for EntropyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Failed => "initialization entropy acquisition failed",
            Self::MissingOsAdapter => "initialization OS entropy adapter is not implemented",
        })
    }
}

impl std::error::Error for EntropyFailure {}

/// One role-specific logical request. Only Ok(32) is a complete sample.
trait InitializationEntropySource {
    fn acquire(
        &mut self,
        role: InitializationKeyRole,
        destination: &mut [u8; 32],
    ) -> Result<usize, EntropyFailure>;
}

struct OsInitializationEntropy;

impl InitializationEntropySource for OsInitializationEntropy {
    fn acquire(
        &mut self,
        _role: InitializationKeyRole,
        destination: &mut [u8; 32],
    ) -> Result<usize, EntropyFailure> {
        // FRONTIER: initialization_os_entropy
        rustix::rand::getrandom(destination, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| EntropyFailure::Failed)
    }
}

pub(crate) struct JournalIntegrityKey(Zeroizing<[u8; 32]>);
struct PortableReservationKey(Zeroizing<[u8; 32]>);

#[cfg(test)]
pub(crate) fn test_journal_integrity_key(bytes: [u8; 32]) -> JournalIntegrityKey {
    JournalIntegrityKey(Zeroizing::new(bytes))
}

#[cfg(test)]
pub(crate) fn test_state_mac_key_wire(
    key: &JournalIntegrityKey,
    reference: msgriver_core::canon::MacKeyRef,
) -> [u8; 106] {
    state_mac_key_file::encode_state_mac_key_file(
        key,
        reference,
        &state_mac_key_file::StateMacKeySecret(Zeroizing::new([0x5a; 32])),
    )
    .expect("synthetic state-key wire")
}

/// Private fixed-width capability that is the sole value allowed to cross from
/// the journal-key boundary into the allocator core.
struct JournalNamespaceCapability([u8; 24]);

const RESOURCE_INCARNATION_NAMESPACE_LABEL: &[u8] = b"msgriver/resource-incarnation-namespace/v1";

/// The derivation failure is deliberately static: journal-key material never
/// appears in a diagnostic while this private boundary is unavailable.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JournalNamespaceError {
    MissingDerivation,
}

impl JournalIntegrityKey {
    /// Derive the sole core-facing namespace capability from this host-local
    /// key. No generic MAC, key identifier, or caller-controlled input exists
    /// at this boundary.
    fn derive_resource_incarnation_namespace_v1(
        &self,
    ) -> Result<JournalNamespaceCapability, JournalNamespaceError> {
        // FRONTIER: journal_namespace_derivation
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0[..])
            .map_err(|_| JournalNamespaceError::MissingDerivation)?;
        mac.update(RESOURCE_INCARNATION_NAMESPACE_LABEL);
        let digest = mac.finalize().into_bytes();
        let mut namespace = [0; 24];
        namespace.copy_from_slice(&digest[..24]);
        Ok(JournalNamespaceCapability(namespace))
    }
}

impl JournalNamespaceProvider for JournalNamespaceCapability {
    fn derive_resource_incarnation_namespace_v1(&self) -> [u8; 24] {
        self.0
    }
}

struct InitializationKeyPair {
    journal_integrity: JournalIntegrityKey,
    portable_reservation: PortableReservationKey,
}

impl fmt::Debug for JournalIntegrityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JournalIntegrityKey([REDACTED])")
    }
}

impl fmt::Debug for PortableReservationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PortableReservationKey([REDACTED])")
    }
}

impl fmt::Debug for InitializationKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InitializationKeyPair([REDACTED])")
    }
}

/// Closed failures cannot return either individual key or provider diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitializationKeyPairError {
    Entropy(InitializationKeyRole),
    Incomplete(InitializationKeyRole),
    Zero(InitializationKeyRole),
    Equal,
    MissingAcquisition,
}

impl fmt::Display for InitializationKeyPairError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Entropy(_) => "initialization key entropy failed",
            Self::Incomplete(_) => "initialization key sample is incomplete",
            Self::Zero(_) => "initialization key sample is zero",
            Self::Equal => "initialization key samples are equal",
            Self::MissingAcquisition => "initialization key-pair acquisition is not implemented",
        })
    }
}

impl std::error::Error for InitializationKeyPairError {}

/// The real adapter uses exactly the same acquisition/validation path as injection.
fn acquire_initialization_key_pair() -> Result<InitializationKeyPair, InitializationKeyPairError> {
    acquire_initialization_key_pair_with(&mut OsInitializationEntropy)
}

fn acquire_initialization_key_pair_with(
    source: &mut dyn InitializationEntropySource,
) -> Result<InitializationKeyPair, InitializationKeyPairError> {
    // FRONTIER: initialization_key_pair_acquisition
    let mut journal_integrity = Zeroizing::new([0; 32]);
    let journal_completion = source
        .acquire(
            InitializationKeyRole::JournalIntegrity,
            &mut journal_integrity,
        )
        .map_err(|_| {
            InitializationKeyPairError::Entropy(InitializationKeyRole::JournalIntegrity)
        })?;
    if journal_completion != journal_integrity.len() {
        return Err(InitializationKeyPairError::Incomplete(
            InitializationKeyRole::JournalIntegrity,
        ));
    }
    if journal_integrity.iter().all(|byte| *byte == 0) {
        return Err(InitializationKeyPairError::Zero(
            InitializationKeyRole::JournalIntegrity,
        ));
    }

    let mut portable_reservation = Zeroizing::new([0; 32]);
    let reservation_completion = source
        .acquire(
            InitializationKeyRole::PortableReservation,
            &mut portable_reservation,
        )
        .map_err(|_| {
            InitializationKeyPairError::Entropy(InitializationKeyRole::PortableReservation)
        })?;
    if reservation_completion != portable_reservation.len() {
        return Err(InitializationKeyPairError::Incomplete(
            InitializationKeyRole::PortableReservation,
        ));
    }
    if portable_reservation.iter().all(|byte| *byte == 0) {
        return Err(InitializationKeyPairError::Zero(
            InitializationKeyRole::PortableReservation,
        ));
    }
    if journal_integrity == portable_reservation {
        return Err(InitializationKeyPairError::Equal);
    }

    Ok(InitializationKeyPair {
        journal_integrity: JournalIntegrityKey(journal_integrity),
        portable_reservation: PortableReservationKey(portable_reservation),
    })
}

#[cfg(test)]
#[path = "red_initialization_key_pair.rs"]
mod red_initialization_key_pair;

#[cfg(test)]
#[path = "red_journal_namespace.rs"]
mod red_journal_namespace;
