//! Task 0015 private, in-memory control-journal header boundary.
//!
//! This child owns only the authenticated header component. The complete
//! journal image, its filesystem publication, checkpoint, tail, records, and
//! allocator intent remain separate future boundaries.

use super::JournalIntegrityKey;
use hmac::{Hmac, Mac};
use msgriver_core::generation::OwnerNamespace;
use sha2::Sha256;
use std::fmt;

const MAGIC: [u8; 16] = *b"MSGRIVER-CJH\0\0\0\0";
const FORMAT_VERSION: u16 = 1;
const KEY_FORMAT_VERSION: u16 = 1;
const MAX_CONTROL_IMAGE_BYTES: u32 = 8 * 1024 * 1024;
const MAX_CONTROL_HEADER_BYTES: u32 = 16 * 1024;
const MAX_CONTROL_CHECKPOINT_BYTES: u32 = 6 * 1024 * 1024 - MAX_CONTROL_HEADER_BYTES;
const MAX_CONTROL_ORDINARY_CHECKPOINT_BYTES: u32 = 4 * 1024 * 1024 - MAX_CONTROL_HEADER_BYTES;
const MAX_CONTROL_RECONCILIATION_CHECKPOINT_BYTES: u32 = 2 * 1024 * 1024;
const MAX_CONTROL_CHECKPOINT_ENTRIES: u32 = 4_096;
const MAX_CONTROL_TAIL_BYTES: u32 = 2 * 1024 * 1024;
const MAX_CONTROL_TAIL_RECORDS: u32 = 128;
const MAX_CONTROL_RECORD_BYTES: u32 = 16 * 1024;
const HEADER_AUTH_LABEL: &[u8] = b"msgriver/control-journal-header/v1";
const PREFIX_BYTES: usize = 88;
const TAG_BYTES: usize = 32;
const WIRE_BYTES: usize = PREFIX_BYTES + TAG_BYTES;

/// Private authenticated facts that every later complete journal image must
/// embed verbatim. No caller can create a header with alternate layout or
/// namespace facts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ControlJournalHeader {
    pub(super) owner_namespace: OwnerNamespace,
    pub(super) branch_serial_high_water: u64,
}

/// Closed diagnostics deliberately omit paths, raw bytes, and key details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlJournalHeaderError {
    MissingControlJournalHeader,
    InvalidHeader,
}

impl fmt::Display for ControlJournalHeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingControlJournalHeader => "control journal header is not implemented",
            Self::InvalidHeader => "control journal header is invalid",
        })
    }
}

impl std::error::Error for ControlJournalHeaderError {}

impl JournalIntegrityKey {
    /// Construct the unique fresh authenticated-header facts. The only
    /// namespace source is this private journal key's fixed Task 0013 path.
    pub(super) fn fresh_control_journal_header(
        &self,
    ) -> Result<ControlJournalHeader, ControlJournalHeaderError> {
        let namespace = self
            .derive_resource_incarnation_namespace_v1()
            .map_err(|_| ControlJournalHeaderError::InvalidHeader)?;
        Ok(ControlJournalHeader {
            owner_namespace: OwnerNamespace::from_bytes(namespace.0),
            branch_serial_high_water: 0,
        })
    }

    /// Construct the only header facts admitted to a complete image owner.
    /// The owner namespace remains derived here; callers may advance only the
    /// source-defined branch high-water value.
    pub(super) fn control_journal_header_with_branch_high_water(
        &self,
        branch_serial_high_water: u64,
    ) -> Result<ControlJournalHeader, ControlJournalHeaderError> {
        let mut header = self.fresh_control_journal_header()?;
        header.branch_serial_high_water = branch_serial_high_water;
        Ok(header)
    }

    /// Encode one private header under this exact journal key. No generic MAC
    /// method, key identity, caller domain, or output buffer is exposed.
    pub(super) fn encode_control_journal_header(
        &self,
        header: ControlJournalHeader,
    ) -> Result<[u8; WIRE_BYTES], ControlJournalHeaderError> {
        if header.owner_namespace != self.fresh_control_journal_header()?.owner_namespace {
            return Err(ControlJournalHeaderError::InvalidHeader);
        }
        let prefix = Self::encode_prefix(header);
        let tag = self.header_tag(&prefix)?;
        let mut wire = [0; WIRE_BYTES];
        wire[..PREFIX_BYTES].copy_from_slice(&prefix);
        wire[PREFIX_BYTES..].copy_from_slice(&tag);
        Ok(wire)
    }

    /// Authenticate and decode only the fixed header wire under this same
    /// journal key, recomputing its namespace before returning any value.
    pub(super) fn decode_control_journal_header(
        &self,
        wire: &[u8],
    ) -> Result<ControlJournalHeader, ControlJournalHeaderError> {
        if wire.len() != WIRE_BYTES {
            return Err(ControlJournalHeaderError::InvalidHeader);
        }
        let prefix: [u8; PREFIX_BYTES] = wire[..PREFIX_BYTES]
            .try_into()
            .map_err(|_| ControlJournalHeaderError::InvalidHeader)?;
        self.verify_header_tag(&prefix, &wire[PREFIX_BYTES..])?;
        if prefix[..16] != MAGIC
            || u16::from_be_bytes([prefix[16], prefix[17]]) != FORMAT_VERSION
            || u16::from_be_bytes([prefix[18], prefix[19]]) != KEY_FORMAT_VERSION
        {
            return Err(ControlJournalHeaderError::InvalidHeader);
        }
        let expected_layout = [
            MAX_CONTROL_IMAGE_BYTES,
            MAX_CONTROL_HEADER_BYTES,
            MAX_CONTROL_CHECKPOINT_BYTES,
            MAX_CONTROL_ORDINARY_CHECKPOINT_BYTES,
            MAX_CONTROL_RECONCILIATION_CHECKPOINT_BYTES,
            MAX_CONTROL_CHECKPOINT_ENTRIES,
            MAX_CONTROL_TAIL_BYTES,
            MAX_CONTROL_TAIL_RECORDS,
            MAX_CONTROL_RECORD_BYTES,
        ];
        for (index, expected) in expected_layout.into_iter().enumerate() {
            let offset = 20 + index * 4;
            if u32::from_be_bytes([
                prefix[offset],
                prefix[offset + 1],
                prefix[offset + 2],
                prefix[offset + 3],
            ]) != expected
            {
                return Err(ControlJournalHeaderError::InvalidHeader);
            }
        }
        let mut namespace = [0; 24];
        namespace.copy_from_slice(&prefix[56..80]);
        let owner_namespace = OwnerNamespace::from_bytes(namespace);
        if owner_namespace != self.fresh_control_journal_header()?.owner_namespace {
            return Err(ControlJournalHeaderError::InvalidHeader);
        }
        Ok(ControlJournalHeader {
            owner_namespace,
            branch_serial_high_water: u64::from_be_bytes([
                prefix[80], prefix[81], prefix[82], prefix[83], prefix[84], prefix[85], prefix[86],
                prefix[87],
            ]),
        })
    }

    fn encode_prefix(header: ControlJournalHeader) -> [u8; PREFIX_BYTES] {
        let mut prefix = [0; PREFIX_BYTES];
        prefix[..16].copy_from_slice(&MAGIC);
        prefix[16..18].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        prefix[18..20].copy_from_slice(&KEY_FORMAT_VERSION.to_be_bytes());
        for (index, value) in [
            MAX_CONTROL_IMAGE_BYTES,
            MAX_CONTROL_HEADER_BYTES,
            MAX_CONTROL_CHECKPOINT_BYTES,
            MAX_CONTROL_ORDINARY_CHECKPOINT_BYTES,
            MAX_CONTROL_RECONCILIATION_CHECKPOINT_BYTES,
            MAX_CONTROL_CHECKPOINT_ENTRIES,
            MAX_CONTROL_TAIL_BYTES,
            MAX_CONTROL_TAIL_RECORDS,
            MAX_CONTROL_RECORD_BYTES,
        ]
        .into_iter()
        .enumerate()
        {
            let offset = 20 + index * 4;
            prefix[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        prefix[56..80].copy_from_slice(&header.owner_namespace.as_bytes());
        prefix[80..88].copy_from_slice(&header.branch_serial_high_water.to_be_bytes());
        prefix
    }

    /// This is deliberately not a reusable MAC surface: one fixed label and
    /// one fixed header prefix are the only inputs admitted at this boundary.
    fn header_tag(
        &self,
        prefix: &[u8; PREFIX_BYTES],
    ) -> Result<[u8; TAG_BYTES], ControlJournalHeaderError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0[..])
            .map_err(|_| ControlJournalHeaderError::InvalidHeader)?;
        mac.update(HEADER_AUTH_LABEL);
        mac.update(prefix);
        let tag = mac.finalize().into_bytes();
        let mut output = [0; TAG_BYTES];
        output.copy_from_slice(&tag);
        Ok(output)
    }

    fn verify_header_tag(
        &self,
        prefix: &[u8; PREFIX_BYTES],
        tag: &[u8],
    ) -> Result<(), ControlJournalHeaderError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0[..])
            .map_err(|_| ControlJournalHeaderError::InvalidHeader)?;
        mac.update(HEADER_AUTH_LABEL);
        mac.update(prefix);
        mac.verify_slice(tag)
            .map_err(|_| ControlJournalHeaderError::InvalidHeader)
    }
}

#[cfg(test)]
#[path = "red_control_journal_header.rs"]
mod red_control_journal_header;
