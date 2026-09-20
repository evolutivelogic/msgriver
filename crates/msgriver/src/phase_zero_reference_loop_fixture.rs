//! Structural-GREEN fixture kernel for the future Phase 0B RED.
//!
//! This fixture is the only implementation in this increment.  It is not a
//! callback parser or provider adapter: it models a typed durable boundary,
//! exact checkpoint stops, and reconstruction of volatile captures after a
//! restart so the later RED can inspect effects independently.

use crate::phase_zero::reference_loop::{
    AlertCapture, CandidateKind, DurableState, EventKind, EvidenceEvent, ProviderBinding,
    ProviderCapture, Receipt, ReferenceLoopRuntime, RegisteredTemplate, RuntimeError, RuntimeStop,
    SafeReference, Tombstone, TransactionCheckpoint, V1Fact,
};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const SNAPSHOT_MAGIC: &[u8; 8] = b"MSGRIV01";
const SNAPSHOT_MAX_BYTES: usize = 16 * 1024 * 1024;
const SNAPSHOT_MAX_ITEMS: usize = 65_536;
const SNAPSHOT_MAX_REFERENCE_BYTES: usize = 256;

#[derive(Debug)]
pub(crate) enum SnapshotError {
    Invalid,
}

struct SnapshotEncoder {
    bytes: Vec<u8>,
    items: usize,
}

impl SnapshotEncoder {
    fn new() -> Self {
        Self {
            bytes: SNAPSHOT_MAGIC.to_vec(),
            items: 0,
        }
    }

    fn put(&mut self, value: &[u8]) -> Result<(), SnapshotError> {
        let end = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(SnapshotError::Invalid)?;
        if end > SNAPSHOT_MAX_BYTES {
            return Err(SnapshotError::Invalid);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn byte(&mut self, value: u8) -> Result<(), SnapshotError> {
        self.put(&[value])
    }

    fn boolean(&mut self, value: bool) -> Result<(), SnapshotError> {
        self.byte(u8::from(value))
    }

    fn u32(&mut self, value: u32) -> Result<(), SnapshotError> {
        self.put(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), SnapshotError> {
        self.put(&value.to_le_bytes())
    }

    fn i64(&mut self, value: i64) -> Result<(), SnapshotError> {
        self.put(&value.to_le_bytes())
    }

    fn count(&mut self, value: usize) -> Result<(), SnapshotError> {
        self.items = self
            .items
            .checked_add(value)
            .ok_or(SnapshotError::Invalid)?;
        if self.items > SNAPSHOT_MAX_ITEMS {
            return Err(SnapshotError::Invalid);
        }
        self.u32(u32::try_from(value).map_err(|_| SnapshotError::Invalid)?)
    }

    fn reference(&mut self, value: &SafeReference) -> Result<(), SnapshotError> {
        let bytes = value.as_str().as_bytes();
        if bytes.is_empty() || bytes.len() > SNAPSHOT_MAX_REFERENCE_BYTES {
            return Err(SnapshotError::Invalid);
        }
        SafeReference::parse(value.as_str()).map_err(|_| SnapshotError::Invalid)?;
        self.u32(u32::try_from(bytes.len()).map_err(|_| SnapshotError::Invalid)?)?;
        self.put(bytes)
    }
}

struct SnapshotDecoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
    items: usize,
}

impl<'a> SnapshotDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, SnapshotError> {
        if bytes.len() > SNAPSHOT_MAX_BYTES || bytes.get(..8) != Some(SNAPSHOT_MAGIC) {
            return Err(SnapshotError::Invalid);
        }
        Ok(Self {
            bytes,
            cursor: 8,
            items: 0,
        })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SnapshotError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(SnapshotError::Invalid)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(SnapshotError::Invalid)?;
        self.cursor = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, SnapshotError> {
        Ok(self.take(1)?[0])
    }
    fn boolean(&mut self) -> Result<bool, SnapshotError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(SnapshotError::Invalid),
        }
    }
    fn u32(&mut self) -> Result<u32, SnapshotError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| SnapshotError::Invalid)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, SnapshotError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| SnapshotError::Invalid)?,
        ))
    }
    fn i64(&mut self) -> Result<i64, SnapshotError> {
        Ok(i64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| SnapshotError::Invalid)?,
        ))
    }
    fn count(&mut self) -> Result<usize, SnapshotError> {
        let count = usize::try_from(self.u32()?).map_err(|_| SnapshotError::Invalid)?;
        self.items = self
            .items
            .checked_add(count)
            .ok_or(SnapshotError::Invalid)?;
        (self.items <= SNAPSHOT_MAX_ITEMS)
            .then_some(count)
            .ok_or(SnapshotError::Invalid)
    }
    fn reference(&mut self) -> Result<SafeReference, SnapshotError> {
        let length = usize::try_from(self.u32()?).map_err(|_| SnapshotError::Invalid)?;
        if length == 0 || length > SNAPSHOT_MAX_REFERENCE_BYTES {
            return Err(SnapshotError::Invalid);
        }
        let text = std::str::from_utf8(self.take(length)?).map_err(|_| SnapshotError::Invalid)?;
        SafeReference::parse(text).map_err(|_| SnapshotError::Invalid)
    }
}

fn encode_candidate_kind(
    encoder: &mut SnapshotEncoder,
    value: CandidateKind,
) -> Result<(), SnapshotError> {
    encoder.byte(match value {
        CandidateKind::InboundMessage => 0,
        CandidateKind::OutboundStatus => 1,
    })
}

fn decode_candidate_kind(
    decoder: &mut SnapshotDecoder<'_>,
) -> Result<CandidateKind, SnapshotError> {
    match decoder.byte()? {
        0 => Ok(CandidateKind::InboundMessage),
        1 => Ok(CandidateKind::OutboundStatus),
        _ => Err(SnapshotError::Invalid),
    }
}

fn encode_receipt(encoder: &mut SnapshotEncoder, value: &Receipt) -> Result<(), SnapshotError> {
    encoder.put(&value.callback_key)?;
    encoder.u64(value.sender_generation)?;
    encode_candidate_kind(encoder, value.kind)?;
    encoder.i64(value.received_at)
}

fn decode_receipt(decoder: &mut SnapshotDecoder<'_>) -> Result<Receipt, SnapshotError> {
    let callback_key: [u8; 32] = decoder
        .take(32)?
        .try_into()
        .map_err(|_| SnapshotError::Invalid)?;
    Ok(Receipt {
        callback_key,
        sender_generation: decoder.u64()?,
        kind: decode_candidate_kind(decoder)?,
        received_at: decoder.i64()?,
    })
}

fn encode_event_kind(encoder: &mut SnapshotEncoder, value: EventKind) -> Result<(), SnapshotError> {
    encoder.byte(match value {
        EventKind::MatchedReply => 0,
        EventKind::UnmatchedReply => 1,
        EventKind::StatusSent => 2,
        EventKind::StatusDelivered => 3,
        EventKind::StatusRead => 4,
        EventKind::StatusFailed => 5,
        EventKind::RetentionDisposition => 6,
        EventKind::ServiceWindowDisposition => 7,
        EventKind::OutboundOutcome => 8,
    })
}

fn decode_event_kind(decoder: &mut SnapshotDecoder<'_>) -> Result<EventKind, SnapshotError> {
    match decoder.byte()? {
        0 => Ok(EventKind::MatchedReply),
        1 => Ok(EventKind::UnmatchedReply),
        2 => Ok(EventKind::StatusSent),
        3 => Ok(EventKind::StatusDelivered),
        4 => Ok(EventKind::StatusRead),
        5 => Ok(EventKind::StatusFailed),
        6 => Ok(EventKind::RetentionDisposition),
        7 => Ok(EventKind::ServiceWindowDisposition),
        8 => Ok(EventKind::OutboundOutcome),
        _ => Err(SnapshotError::Invalid),
    }
}

fn encode_service_window_state(
    encoder: &mut SnapshotEncoder,
    value: crate::phase_zero::reference_loop::ServiceWindowState,
) -> Result<(), SnapshotError> {
    encoder.byte(match value {
        crate::phase_zero::reference_loop::ServiceWindowState::Active => 0,
        crate::phase_zero::reference_loop::ServiceWindowState::Unknown => 1,
        crate::phase_zero::reference_loop::ServiceWindowState::Expired => 2,
    })
}

fn decode_service_window_state(
    decoder: &mut SnapshotDecoder<'_>,
) -> Result<crate::phase_zero::reference_loop::ServiceWindowState, SnapshotError> {
    match decoder.byte()? {
        0 => Ok(crate::phase_zero::reference_loop::ServiceWindowState::Active),
        1 => Ok(crate::phase_zero::reference_loop::ServiceWindowState::Unknown),
        2 => Ok(crate::phase_zero::reference_loop::ServiceWindowState::Expired),
        _ => Err(SnapshotError::Invalid),
    }
}

fn encode_provider_outcome(
    encoder: &mut SnapshotEncoder,
    value: crate::phase_zero::reference_loop::ProviderOutcomeClass,
) -> Result<(), SnapshotError> {
    encoder.byte(match value {
        crate::phase_zero::reference_loop::ProviderOutcomeClass::Permanent => 0,
        crate::phase_zero::reference_loop::ProviderOutcomeClass::AuthOrConfig => 1,
        crate::phase_zero::reference_loop::ProviderOutcomeClass::RateLimited => 2,
        crate::phase_zero::reference_loop::ProviderOutcomeClass::Transient => 3,
        crate::phase_zero::reference_loop::ProviderOutcomeClass::Ambiguous => 4,
    })
}

fn decode_provider_outcome(
    decoder: &mut SnapshotDecoder<'_>,
) -> Result<crate::phase_zero::reference_loop::ProviderOutcomeClass, SnapshotError> {
    match decoder.byte()? {
        0 => Ok(crate::phase_zero::reference_loop::ProviderOutcomeClass::Permanent),
        1 => Ok(crate::phase_zero::reference_loop::ProviderOutcomeClass::AuthOrConfig),
        2 => Ok(crate::phase_zero::reference_loop::ProviderOutcomeClass::RateLimited),
        3 => Ok(crate::phase_zero::reference_loop::ProviderOutcomeClass::Transient),
        4 => Ok(crate::phase_zero::reference_loop::ProviderOutcomeClass::Ambiguous),
        _ => Err(SnapshotError::Invalid),
    }
}

fn encode_provider_binding(
    encoder: &mut SnapshotEncoder,
    value: &ProviderBinding,
) -> Result<(), SnapshotError> {
    encoder.u64(value.sender_generation)?;
    encoder.reference(&value.provider_message_id)
}

fn decode_provider_binding(
    decoder: &mut SnapshotDecoder<'_>,
) -> Result<ProviderBinding, SnapshotError> {
    Ok(ProviderBinding {
        sender_generation: decoder.u64()?,
        provider_message_id: decoder.reference()?,
    })
}

fn encode_outbound_pin(
    encoder: &mut SnapshotEncoder,
    value: &crate::phase_zero::reference_loop::OutboundPin,
) -> Result<(), SnapshotError> {
    encoder.reference(&value.attempt_reference)?;
    encoder.u64(value.sender_generation)?;
    encoder.u64(value.endpoint_generation)?;
    encoder.u64(value.credential_generation)?;
    encoder.u64(value.template_allowlist_generation)
}

fn decode_outbound_pin(
    decoder: &mut SnapshotDecoder<'_>,
) -> Result<crate::phase_zero::reference_loop::OutboundPin, SnapshotError> {
    Ok(crate::phase_zero::reference_loop::OutboundPin {
        attempt_reference: decoder.reference()?,
        sender_generation: decoder.u64()?,
        endpoint_generation: decoder.u64()?,
        credential_generation: decoder.u64()?,
        template_allowlist_generation: decoder.u64()?,
    })
}

fn encode_event(encoder: &mut SnapshotEncoder, value: &EvidenceEvent) -> Result<(), SnapshotError> {
    encode_event_kind(encoder, value.kind.clone())?;
    encoder.reference(&value.reference)?;
    encoder.u64(value.sender_generation)?;
    encoder.boolean(value.provider_occurred_at.is_some())?;
    if let Some(provider_occurred_at) = value.provider_occurred_at {
        encoder.i64(provider_occurred_at)?;
    }
    encoder.u64(value.receipt_order)
}

fn decode_event(decoder: &mut SnapshotDecoder<'_>) -> Result<EvidenceEvent, SnapshotError> {
    let kind = decode_event_kind(decoder)?;
    let reference = decoder.reference()?;
    let sender_generation = decoder.u64()?;
    let provider_occurred_at = decoder.boolean()?.then(|| decoder.i64()).transpose()?;
    Ok(EvidenceEvent {
        kind,
        reference,
        sender_generation,
        provider_occurred_at,
        receipt_order: decoder.u64()?,
    })
}

fn encode_alert_intent(
    encoder: &mut SnapshotEncoder,
    value: &crate::phase_zero::reference_loop::AlertIntent,
) -> Result<(), SnapshotError> {
    encoder.reference(&value.event_reference)?;
    encoder.boolean(value.matched)?;
    encoder.i64(value.safe_timestamp)?;
    encoder.boolean(value.leased)?;
    encoder.u64(value.lease_fence)?;
    encoder.boolean(value.lease_expires_at.is_some())?;
    if let Some(lease_expires_at) = value.lease_expires_at {
        encoder.i64(lease_expires_at)?;
    }
    encoder.u32(value.dispatch_attempts)?;
    encoder.boolean(value.delivered)?;
    encoder.boolean(value.ambiguous_dispatch)
}

fn decode_alert_intent(
    decoder: &mut SnapshotDecoder<'_>,
) -> Result<crate::phase_zero::reference_loop::AlertIntent, SnapshotError> {
    Ok(crate::phase_zero::reference_loop::AlertIntent {
        event_reference: decoder.reference()?,
        matched: decoder.boolean()?,
        safe_timestamp: decoder.i64()?,
        leased: decoder.boolean()?,
        lease_fence: decoder.u64()?,
        lease_expires_at: decoder.boolean()?.then(|| decoder.i64()).transpose()?,
        dispatch_attempts: decoder.u32()?,
        delivered: decoder.boolean()?,
        ambiguous_dispatch: decoder.boolean()?,
    })
}

fn encode_tombstone(encoder: &mut SnapshotEncoder, value: &Tombstone) -> Result<(), SnapshotError> {
    encoder.put(&value.callback_key)?;
    encoder.u64(value.sender_generation)?;
    encoder.u64(value.key_generation)
}

fn decode_tombstone(decoder: &mut SnapshotDecoder<'_>) -> Result<Tombstone, SnapshotError> {
    let callback_key: [u8; 32] = decoder
        .take(32)?
        .try_into()
        .map_err(|_| SnapshotError::Invalid)?;
    Ok(Tombstone {
        callback_key,
        sender_generation: decoder.u64()?,
        key_generation: decoder.u64()?,
    })
}

fn encode_v1_fact(encoder: &mut SnapshotEncoder, value: V1Fact) -> Result<(), SnapshotError> {
    match value {
        V1Fact::ProviderAccepted {
            attempts,
            uncertain,
        } => {
            encoder.byte(0)?;
            encoder.u32(attempts)?;
            encoder.boolean(uncertain)
        }
        V1Fact::ProviderOutcome {
            class,
            attempts,
            uncertain,
        } => {
            encoder.byte(1)?;
            encode_provider_outcome(encoder, class)?;
            encoder.u32(attempts)?;
            encoder.boolean(uncertain)
        }
    }
}

fn decode_v1_fact(decoder: &mut SnapshotDecoder<'_>) -> Result<V1Fact, SnapshotError> {
    match decoder.byte()? {
        0 => Ok(V1Fact::ProviderAccepted {
            attempts: decoder.u32()?,
            uncertain: decoder.boolean()?,
        }),
        1 => Ok(V1Fact::ProviderOutcome {
            class: decode_provider_outcome(decoder)?,
            attempts: decoder.u32()?,
            uncertain: decoder.boolean()?,
        }),
        _ => Err(SnapshotError::Invalid),
    }
}

fn encode_sensitive_reply(
    encoder: &mut SnapshotEncoder,
    value: &crate::phase_zero::reference_loop::SensitiveReplyState,
) -> Result<(), SnapshotError> {
    encoder.i64(value.retained_at)?;
    encoder.i64(value.expires_at)?;
    encoder.boolean(value.local_only)
}

fn decode_sensitive_reply(
    decoder: &mut SnapshotDecoder<'_>,
) -> Result<crate::phase_zero::reference_loop::SensitiveReplyState, SnapshotError> {
    Ok(crate::phase_zero::reference_loop::SensitiveReplyState {
        retained_at: decoder.i64()?,
        expires_at: decoder.i64()?,
        local_only: decoder.boolean()?,
    })
}

fn encode_service_window_disposition(
    encoder: &mut SnapshotEncoder,
    value: &crate::phase_zero::reference_loop::ServiceWindowDisposition,
) -> Result<(), SnapshotError> {
    encoder.reference(&value.event_reference)?;
    encoder.boolean(value.prior_event_reference.is_some())?;
    if let Some(prior_event_reference) = &value.prior_event_reference {
        encoder.reference(prior_event_reference)?;
    }
    encode_service_window_state(encoder, value.state)
}

fn decode_service_window_disposition(
    decoder: &mut SnapshotDecoder<'_>,
) -> Result<crate::phase_zero::reference_loop::ServiceWindowDisposition, SnapshotError> {
    let event_reference = decoder.reference()?;
    let prior_event_reference = decoder
        .boolean()?
        .then(|| decoder.reference())
        .transpose()?;
    Ok(
        crate::phase_zero::reference_loop::ServiceWindowDisposition {
            event_reference,
            prior_event_reference,
            state: decode_service_window_state(decoder)?,
        },
    )
}

fn encode_state(state: &DurableState) -> Result<Vec<u8>, SnapshotError> {
    let mut encoder = SnapshotEncoder::new();
    encoder.u64(state.revision)?;
    encoder.count(state.receipts.len())?;
    for value in &state.receipts {
        encode_receipt(&mut encoder, value)?;
    }
    encoder.count(state.bindings.len())?;
    for value in &state.bindings {
        encode_provider_binding(&mut encoder, value)?;
    }
    encoder.count(state.outbound_pins.len())?;
    for value in &state.outbound_pins {
        encode_outbound_pin(&mut encoder, value)?;
    }
    encoder.count(state.events.len())?;
    for value in &state.events {
        encode_event(&mut encoder, value)?;
    }
    encoder.count(state.outbox.len())?;
    for value in &state.outbox {
        encode_alert_intent(&mut encoder, value)?;
    }
    encoder.count(state.tombstones.len())?;
    for value in &state.tombstones {
        encode_tombstone(&mut encoder, value)?;
    }
    encoder.count(state.v1_history.len())?;
    for value in &state.v1_history {
        encode_v1_fact(&mut encoder, *value)?;
    }
    encoder.boolean(state.sensitive_reply.is_some())?;
    if let Some(value) = &state.sensitive_reply {
        encode_sensitive_reply(&mut encoder, value)?;
    }
    encoder.count(state.service_window_dispositions.len())?;
    for value in &state.service_window_dispositions {
        encode_service_window_disposition(&mut encoder, value)?;
    }
    Ok(encoder.bytes)
}

fn decode_values<T>(
    decoder: &mut SnapshotDecoder<'_>,
    decode: impl Fn(&mut SnapshotDecoder<'_>) -> Result<T, SnapshotError>,
) -> Result<Vec<T>, SnapshotError> {
    let count = decoder.count()?;
    (0..count).map(|_| decode(decoder)).collect()
}

fn decode_state(bytes: &[u8]) -> Result<DurableState, SnapshotError> {
    let mut decoder = SnapshotDecoder::new(bytes)?;
    let revision = decoder.u64()?;
    let receipts = decode_values(&mut decoder, decode_receipt)?;
    let bindings = decode_values(&mut decoder, decode_provider_binding)?;
    let outbound_pins = decode_values(&mut decoder, decode_outbound_pin)?;
    let events = decode_values(&mut decoder, decode_event)?;
    let outbox = decode_values(&mut decoder, decode_alert_intent)?;
    let tombstones = decode_values(&mut decoder, decode_tombstone)?;
    let v1_history = decode_values(&mut decoder, decode_v1_fact)?;
    let sensitive_reply = decoder
        .boolean()?
        .then(|| decode_sensitive_reply(&mut decoder))
        .transpose()?;
    let service_window_dispositions =
        decode_values(&mut decoder, decode_service_window_disposition)?;
    if decoder.cursor != bytes.len() {
        return Err(SnapshotError::Invalid);
    }
    Ok(DurableState {
        receipts,
        bindings,
        outbound_pins,
        events,
        outbox,
        tombstones,
        v1_history,
        sensitive_reply,
        service_window_dispositions,
        revision,
    })
}

/// Test-only persistence uses a closed binary snapshot rather than a
/// serialization dependency, so frozen predecessor tests retain their exact
/// dependency graph. A completed snapshot replaces the prior one atomically.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FixtureStore {
    snapshot_path: PathBuf,
}

/// Owns the advisory fixture lock for one critical section. Explicit unlock
/// prevents a child spawned concurrently by another test from prolonging this
/// process's lock through an inherited descriptor before it reaches exec.
struct FixtureStoreLock {
    file: File,
}

impl Drop for FixtureStoreLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl FixtureStore {
    fn initialize(snapshot_path: PathBuf, state: &DurableState) -> Result<Self, SnapshotError> {
        let store = Self { snapshot_path };
        store.persist(state)?;
        Ok(store)
    }

    fn reopen(snapshot_path: PathBuf) -> Result<(Self, DurableState), SnapshotError> {
        let store = Self { snapshot_path };
        let state = store.load()?;
        Ok((store, state))
    }

    fn load(&self) -> Result<DurableState, SnapshotError> {
        let metadata = fs::metadata(&self.snapshot_path).map_err(|_| SnapshotError::Invalid)?;
        if !metadata.is_file()
            || metadata.len()
                > u64::try_from(SNAPSHOT_MAX_BYTES).map_err(|_| SnapshotError::Invalid)?
        {
            return Err(SnapshotError::Invalid);
        }
        let bytes = fs::read(&self.snapshot_path).map_err(|_| SnapshotError::Invalid)?;
        decode_state(&bytes)
    }

    fn replace_if_revision(
        &self,
        expected_revision: u64,
        replacement: &DurableState,
    ) -> Result<(), RuntimeError> {
        let lock = self.acquire_lock()?;
        let result = (|| {
            let current = self.load().map_err(|_| RuntimeError::InvalidFixture)?;
            if current.revision != expected_revision {
                return Err(RuntimeError::RevisionConflict);
            }
            self.persist(replacement)
                .map_err(|_| RuntimeError::InvalidFixture)
        })();
        drop(lock);
        result
    }

    /// Advisory OS lock: unlike a create-new sentinel, it is released by the
    /// kernel if a worker terminates while it owns the critical section. The
    /// lock pathname intentionally remains in place; unlinking it while a
    /// waiter owns its inode would create a second, independent lock domain.
    fn lock_path(&self) -> Result<PathBuf, RuntimeError> {
        let parent = self
            .snapshot_path
            .parent()
            .ok_or(RuntimeError::InvalidFixture)?;
        let filename = self
            .snapshot_path
            .file_name()
            .ok_or(RuntimeError::InvalidFixture)?;
        let mut lock_name = OsString::from(".");
        lock_name.push(filename);
        lock_name.push(".msgriver-phase0-fixture.lock");
        Ok(parent.join(lock_name))
    }

    fn acquire_lock(&self) -> Result<FixtureStoreLock, RuntimeError> {
        let lock_path = self.lock_path()?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|_| RuntimeError::InvalidFixture)?;
        lock.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => RuntimeError::RevisionConflict,
            std::fs::TryLockError::Error(_) => RuntimeError::InvalidFixture,
        })?;
        Ok(FixtureStoreLock { file: lock })
    }

    fn persist(&self, state: &DurableState) -> Result<(), SnapshotError> {
        let parent = self.snapshot_path.parent().ok_or(SnapshotError::Invalid)?;
        let parent_metadata = fs::metadata(parent).map_err(|_| SnapshotError::Invalid)?;
        if !parent_metadata.is_dir() {
            return Err(SnapshotError::Invalid);
        }
        let bytes = encode_state(state)?;
        for attempt in 0..32_u32 {
            let temporary = parent.join(format!(
                ".msgriver-phase0-{}-{}-{}.tmp",
                std::process::id(),
                state.revision,
                attempt
            ));
            let mut file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(SnapshotError::Invalid),
            };
            let write_result = file
                .write_all(&bytes)
                .and_then(|()| file.sync_all())
                .and_then(|()| fs::rename(&temporary, &self.snapshot_path))
                .and_then(|()| File::open(parent))
                .and_then(|directory| directory.sync_all());
            if write_result.is_ok() {
                return Ok(());
            }
            let _ = fs::remove_file(&temporary);
            return Err(SnapshotError::Invalid);
        }
        Err(SnapshotError::Invalid)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct VolatileState {
    provider: Vec<ProviderCapture>,
    alerts: Vec<AlertCapture>,
    attempted_alerts: Vec<AlertCapture>,
    staged_candidates: Vec<Receipt>,
    staged_batch: Option<Vec<Receipt>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct FixtureKernel {
    durable: DurableState,
    volatile: VolatileState,
    stop_at: Option<TransactionCheckpoint>,
    alert_unavailable: bool,
    store: Option<FixtureStore>,
}

impl FixtureKernel {
    pub(crate) fn with_durable(durable: DurableState) -> Self {
        Self {
            durable,
            ..Self::default()
        }
    }

    pub(crate) fn with_store(
        durable: DurableState,
        snapshot_path: &Path,
    ) -> Result<Self, SnapshotError> {
        let store = FixtureStore::initialize(snapshot_path.to_owned(), &durable)?;
        Ok(Self {
            durable,
            store: Some(store),
            ..Self::default()
        })
    }

    pub(crate) fn reopen_store(snapshot_path: &Path) -> Result<Self, SnapshotError> {
        let (store, durable) = FixtureStore::reopen(snapshot_path.to_owned())?;
        Ok(Self {
            durable,
            store: Some(store),
            ..Self::default()
        })
    }

    fn refresh_from_store(&mut self) -> Result<(), RuntimeError> {
        if let Some(store) = &self.store {
            self.durable = store.load().map_err(|_| RuntimeError::InvalidFixture)?;
        }
        Ok(())
    }

    fn persist_replacement(
        &self,
        expected_revision: u64,
        replacement: &DurableState,
    ) -> Result<(), RuntimeError> {
        self.store
            .as_ref()
            .map(|store| store.replace_if_revision(expected_revision, replacement))
            .transpose()?;
        Ok(())
    }

    pub(crate) fn inject_stop(&mut self, checkpoint: TransactionCheckpoint) {
        self.stop_at = Some(checkpoint);
    }

    pub(crate) fn inject_alert_unavailable(&mut self) {
        self.alert_unavailable = true;
    }

    pub(crate) fn restart(self) -> Self {
        Self {
            durable: self.durable,
            volatile: VolatileState::default(),
            stop_at: None,
            alert_unavailable: self.alert_unavailable,
            store: self.store,
        }
    }

    pub(crate) fn durable(&self) -> &DurableState {
        &self.durable
    }

    pub(crate) fn provider_captures(&self) -> &[ProviderCapture] {
        &self.volatile.provider
    }

    pub(crate) fn alert_captures(&self) -> &[AlertCapture] {
        &self.volatile.alerts
    }

    pub(crate) fn attempted_alert_captures(&self) -> &[AlertCapture] {
        &self.volatile.attempted_alerts
    }

    pub(crate) fn staged_candidates(&self) -> &[Receipt] {
        &self.volatile.staged_candidates
    }

    fn staged_batch_is_exact_receipt_delta(&self, replacement: &DurableState) -> bool {
        let Some(batch) = &self.volatile.staged_batch else {
            return true;
        };
        let mut expected = self.durable.receipts.clone();
        expected.extend(batch.iter().cloned());
        if expected.len() != replacement.receipts.len() {
            return false;
        }
        let mut remaining = replacement.receipts.clone();
        expected.iter().all(|candidate| {
            remaining
                .iter()
                .position(|receipt| receipt == candidate)
                .map(|position| {
                    remaining.remove(position);
                })
                .is_some()
        })
    }

    fn record_alert_attempt(capture: &AlertCapture) {
        if std::env::var_os("MSGRIVER_PHASE0_CHILD_EFFECT_LOG").is_some() {
            println!("MSGRIVER_PHASE0_ALERT_ATTEMPT:{}", capture.fixture_record());
        }
    }

    fn stopped(&self, checkpoint: TransactionCheckpoint) -> bool {
        self.stop_at == Some(checkpoint)
    }

    fn stop_for(checkpoint: TransactionCheckpoint) -> RuntimeStop {
        match checkpoint {
            TransactionCheckpoint::BeforeCommit => RuntimeStop::BeforeCommit,
            TransactionCheckpoint::AfterReceiptInsert => RuntimeStop::AfterReceiptInsert,
            TransactionCheckpoint::AfterCommitBeforeAck => RuntimeStop::AfterCommitBeforeAck,
            TransactionCheckpoint::BeforeDispatchLease => RuntimeStop::BeforeDispatchLease,
            TransactionCheckpoint::AfterDispatchSend => RuntimeStop::AfterDispatchSend,
        }
    }

    /// The ordinary fixture returns a typed stop so focused structural tests
    /// can inspect it. A dedicated worker child sets this private switch to
    /// die *inside* the named barrier, before unwinding locks or volatile
    /// state; the parent then has only persisted evidence to inspect.
    fn stop_or_terminate(&self, checkpoint: TransactionCheckpoint) -> RuntimeError {
        if std::env::var_os("MSGRIVER_PHASE0_TERMINATE_AT_CHECKPOINT").is_some() {
            std::process::exit(93);
        }
        RuntimeError::Stop(Self::stop_for(checkpoint))
    }
}

impl ReferenceLoopRuntime for FixtureKernel {
    fn durable_state(&self) -> DurableState {
        self.durable.clone()
    }

    fn replace_durable_state(
        &mut self,
        expected_revision: u64,
        mut replacement: DurableState,
    ) -> Result<(), RuntimeError> {
        self.refresh_from_store()?;
        if expected_revision != self.durable.revision {
            return Err(RuntimeError::RevisionConflict);
        }
        if !self.staged_batch_is_exact_receipt_delta(&replacement) {
            return Err(RuntimeError::InvalidFixture);
        }
        if self.stopped(TransactionCheckpoint::BeforeCommit) {
            return Err(self.stop_or_terminate(TransactionCheckpoint::BeforeCommit));
        }
        // This checkpoint is deliberately after validation of the literal
        // receipt delta but before its atomic snapshot write. It therefore
        // models an interrupted callback transaction, not a free-standing
        // test-only vector mutation.
        if self.volatile.staged_batch.is_some()
            && self.stopped(TransactionCheckpoint::AfterReceiptInsert)
        {
            return Err(self.stop_or_terminate(TransactionCheckpoint::AfterReceiptInsert));
        }
        replacement.revision = expected_revision
            .checked_add(1)
            .ok_or(RuntimeError::InvalidFixture)?;
        self.persist_replacement(expected_revision, &replacement)?;
        self.durable = replacement;
        self.volatile.staged_batch = None;
        self.volatile.staged_candidates.clear();
        if self.stopped(TransactionCheckpoint::AfterCommitBeforeAck) {
            return Err(self.stop_or_terminate(TransactionCheckpoint::AfterCommitBeforeAck));
        }
        Ok(())
    }

    fn capture_provider(&mut self, capture: ProviderCapture) -> Result<(), RuntimeError> {
        self.volatile.provider.push(capture);
        if std::env::var_os("MSGRIVER_PHASE0_CHILD_EFFECT_LOG").is_some() {
            println!("MSGRIVER_PHASE0_PROVIDER_CAPTURE");
        }
        if self.stopped(TransactionCheckpoint::AfterDispatchSend) {
            return Err(self.stop_or_terminate(TransactionCheckpoint::AfterDispatchSend));
        }
        Ok(())
    }

    fn stage_callback_candidates(&mut self, candidates: &[Receipt]) -> Result<(), RuntimeError> {
        if candidates.is_empty() {
            return Err(RuntimeError::InvalidFixture);
        }
        if self.volatile.staged_batch.is_some() {
            return Err(RuntimeError::InvalidFixture);
        }
        // This is the pre-commit half of one callback transaction. The later
        // replacement must be the exact prior receipt multiset plus this
        // batch; the receipt-insert checkpoint fires only after that check.
        self.volatile.staged_batch = Some(candidates.to_vec());
        for candidate in candidates {
            self.volatile.staged_candidates.push(candidate.clone());
        }
        Ok(())
    }

    fn capture_alert(
        &mut self,
        capture: AlertCapture,
        lease_fence: u64,
        observed_at: i64,
    ) -> Result<(), RuntimeError> {
        // The externally observable attempt is recorded before every local
        // validation, including a failed durable refresh. A restarted worker
        // cannot erase this witness from its parent-owned child output.
        Self::record_alert_attempt(&capture);
        self.volatile.attempted_alerts.push(capture.clone());
        let lock = self
            .store
            .as_ref()
            .map(FixtureStore::acquire_lock)
            .transpose()?;
        self.refresh_from_store()?;
        let eligible = self.durable.outbox.iter().any(|intent| {
            intent.event_reference == *capture.event_reference()
                && intent.leased
                && !intent.delivered
                && intent.lease_fence == lease_fence
                && intent
                    .lease_expires_at
                    .is_some_and(|lease_expires_at| observed_at < lease_expires_at)
        });
        if !eligible {
            return Err(RuntimeError::InvalidFixture);
        }
        if self.alert_unavailable {
            return Err(RuntimeError::AlertUnavailable);
        }
        if std::env::var_os("MSGRIVER_PHASE0_CHILD_EFFECT_LOG").is_some() {
            println!("MSGRIVER_PHASE0_ALERT_CAPTURE:{}", capture.fixture_record());
        }
        self.volatile.alerts.push(capture);
        // A lease replacement obtains this same OS lock. Keeping it through
        // validation and the fake sink publication makes the pair indivisible
        // from a competing expired-lease recovery in the disk-backed fixture.
        if self.stopped(TransactionCheckpoint::AfterDispatchSend) {
            return Err(self.stop_or_terminate(TransactionCheckpoint::AfterDispatchSend));
        }
        drop(lock);
        Ok(())
    }

    fn lease_alert(
        &mut self,
        event_reference: &SafeReference,
        leased_at: i64,
    ) -> Result<crate::phase_zero::reference_loop::AlertIntent, RuntimeError> {
        self.refresh_from_store()?;
        let mut replacement = self.durable.clone();
        let Some(intent) = replacement.outbox.iter_mut().find(|intent| {
            &intent.event_reference == event_reference
                && !intent.delivered
                && (!intent.leased
                    || intent
                        .lease_expires_at
                        .is_some_and(|lease_expires_at| lease_expires_at <= leased_at))
        }) else {
            return Err(RuntimeError::InvalidFixture);
        };
        if self.stopped(TransactionCheckpoint::BeforeDispatchLease) {
            return Err(self.stop_or_terminate(TransactionCheckpoint::BeforeDispatchLease));
        }
        let was_expired = intent.leased;
        intent.leased = true;
        intent.lease_fence = intent
            .lease_fence
            .checked_add(1)
            .ok_or(RuntimeError::InvalidFixture)?;
        intent.lease_expires_at = Some(
            leased_at
                .checked_add(60)
                .ok_or(RuntimeError::InvalidFixture)?,
        );
        intent.dispatch_attempts = intent
            .dispatch_attempts
            .checked_add(1)
            .ok_or(RuntimeError::InvalidFixture)?;
        intent.ambiguous_dispatch |= was_expired;
        let leased = intent.clone();
        replacement.revision = replacement
            .revision
            .checked_add(1)
            .ok_or(RuntimeError::InvalidFixture)?;
        self.persist_replacement(self.durable.revision, &replacement)?;
        self.durable = replacement;
        Ok(leased)
    }

    fn settle_alert(
        &mut self,
        event_reference: &SafeReference,
        lease_fence: u64,
    ) -> Result<(), RuntimeError> {
        self.refresh_from_store()?;
        let mut replacement = self.durable.clone();
        let Some(intent) = replacement.outbox.iter_mut().find(|intent| {
            &intent.event_reference == event_reference
                && intent.leased
                && !intent.delivered
                && intent.lease_fence == lease_fence
        }) else {
            return Err(RuntimeError::InvalidFixture);
        };
        intent.leased = false;
        intent.lease_expires_at = None;
        intent.delivered = true;
        replacement.revision = replacement
            .revision
            .checked_add(1)
            .ok_or(RuntimeError::InvalidFixture)?;
        self.persist_replacement(self.durable.revision, &replacement)?;
        self.durable = replacement;
        Ok(())
    }
}

#[test]
fn phase_zero_fixture_snapshot_primitives_reject_malformed_encodings() {
    let reference = SafeReference::parse("event-42").expect("fixed safe reference");
    let mut encoder = SnapshotEncoder::new();
    encoder.boolean(true).expect("encode boolean");
    encoder.u32(7).expect("encode u32");
    encoder.u64(9).expect("encode u64");
    encoder.i64(-11).expect("encode i64");
    encoder.count(1).expect("encode count");
    encoder.reference(&reference).expect("encode reference");
    let mut decoder = SnapshotDecoder::new(&encoder.bytes).expect("open snapshot");
    assert!(decoder.boolean().expect("decode boolean"));
    assert_eq!(decoder.u32().expect("decode u32"), 7);
    assert_eq!(decoder.u64().expect("decode u64"), 9);
    assert_eq!(decoder.i64().expect("decode i64"), -11);
    assert_eq!(decoder.count().expect("decode count"), 1);
    assert_eq!(decoder.reference().expect("decode reference"), reference);
    assert_eq!(decoder.cursor, encoder.bytes.len());
    assert!(SnapshotDecoder::new(b"MSGRIV00").is_err());
    assert!(SnapshotDecoder::new(SNAPSHOT_MAGIC).is_ok());
}

#[test]
fn phase_zero_fixture_snapshot_receipt_has_closed_tag_and_exact_bytes() {
    let receipt = Receipt {
        callback_key: [0x42; 32],
        sender_generation: 7,
        kind: CandidateKind::OutboundStatus,
        received_at: -11,
    };
    let mut encoder = SnapshotEncoder::new();
    encode_receipt(&mut encoder, &receipt).expect("encode receipt");
    let mut decoder = SnapshotDecoder::new(&encoder.bytes).expect("open snapshot");
    assert_eq!(
        decode_receipt(&mut decoder).expect("decode receipt"),
        receipt
    );
    let mut malformed = encoder.bytes;
    malformed[8 + 32 + 8] = 2;
    let mut decoder = SnapshotDecoder::new(&malformed).expect("open malformed snapshot");
    assert!(decode_receipt(&mut decoder).is_err());
}

#[test]
fn phase_zero_fixture_snapshot_roundtrips_each_durable_state_variant() {
    let event = SafeReference::parse("event-11").expect("fixed event reference");
    let attempt = SafeReference::parse("event-12").expect("fixed attempt reference");
    let provider = SafeReference::parse("provider-message-13").expect("fixed provider reference");
    let state = DurableState {
        receipts: vec![Receipt {
            callback_key: [0x01; 32],
            sender_generation: 2,
            kind: CandidateKind::InboundMessage,
            received_at: -3,
        }],
        bindings: vec![ProviderBinding {
            sender_generation: 2,
            provider_message_id: provider.clone(),
        }],
        outbound_pins: vec![crate::phase_zero::reference_loop::OutboundPin {
            attempt_reference: attempt,
            sender_generation: 2,
            endpoint_generation: 3,
            credential_generation: 4,
            template_allowlist_generation: 5,
        }],
        events: vec![EvidenceEvent {
            kind: EventKind::MatchedReply,
            reference: event.clone(),
            sender_generation: 2,
            provider_occurred_at: Some(-7),
            receipt_order: 8,
        }],
        outbox: vec![crate::phase_zero::reference_loop::AlertIntent {
            event_reference: event.clone(),
            matched: true,
            safe_timestamp: -9,
            leased: true,
            lease_fence: 1,
            lease_expires_at: Some(17),
            dispatch_attempts: 1,
            delivered: false,
            ambiguous_dispatch: true,
        }],
        tombstones: vec![Tombstone {
            callback_key: [0x0a; 32],
            sender_generation: 2,
            key_generation: 6,
        }],
        v1_history: vec![
            V1Fact::ProviderAccepted {
                attempts: 1,
                uncertain: false,
            },
            V1Fact::ProviderOutcome {
                class: crate::phase_zero::reference_loop::ProviderOutcomeClass::Ambiguous,
                attempts: 2,
                uncertain: true,
            },
        ],
        sensitive_reply: Some(crate::phase_zero::reference_loop::SensitiveReplyState {
            retained_at: 16,
            expires_at: 17,
            local_only: true,
        }),
        service_window_dispositions: vec![
            crate::phase_zero::reference_loop::ServiceWindowDisposition {
                event_reference: event.clone(),
                prior_event_reference: None,
                state: crate::phase_zero::reference_loop::ServiceWindowState::Unknown,
            },
            crate::phase_zero::reference_loop::ServiceWindowDisposition {
                event_reference: SafeReference::parse("event-14")
                    .expect("fixed correction reference"),
                prior_event_reference: Some(event),
                state: crate::phase_zero::reference_loop::ServiceWindowState::Expired,
            },
        ],
        revision: 10,
    };
    let bytes = encode_state(&state).expect("encode durable state");
    assert_eq!(decode_state(&bytes).expect("decode durable state"), state);
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_state(&trailing).is_err());
}

fn fixture_store_root() -> PathBuf {
    for attempt in 0..32_u32 {
        // nosemgrep: rust.lang.security.temp-dir.temp-dir -- test-owned 0700 store is made unique below.
        let root = std::env::temp_dir().join(format!(
            "msgriver-phase0-fixture-{}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test"),
            attempt
        ));
        match fs::create_dir(&root) {
            Ok(()) => {
                #[cfg(unix)]
                fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                    .expect("restrict isolated fixture store");
                return root;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create isolated fixture store: {error}"),
        }
    }
    panic!("allocate isolated fixture store")
}

#[test]
fn phase_zero_fixture_store_reopens_only_completed_snapshot() {
    let root = fixture_store_root();
    let snapshot = root.join("state.bin");
    let mut fixture = FixtureKernel::with_store(
        DurableState {
            revision: 3,
            ..DurableState::default()
        },
        &snapshot,
    )
    .expect("initialize fixture store");
    fixture
        .replace_durable_state(
            3,
            DurableState {
                revision: 3,
                events: vec![EvidenceEvent {
                    kind: EventKind::StatusDelivered,
                    reference: SafeReference::parse("event-15").expect("fixed event reference"),
                    sender_generation: 7,
                    provider_occurred_at: Some(18),
                    receipt_order: 1,
                }],
                ..DurableState::default()
            },
        )
        .expect("persist replacement");
    let reopened = FixtureKernel::reopen_store(&snapshot).expect("reopen completed snapshot");
    assert_eq!(reopened.durable(), fixture.durable());
    assert_eq!(reopened.durable().revision, 4);
    assert!(
        fs::read_dir(&root)
            .expect("read isolated fixture store")
            .all(|entry| {
                matches!(
                    entry
                        .expect("read store entry")
                        .file_name()
                        .as_os_str()
                        .to_str(),
                    Some("state.bin" | ".state.bin.msgriver-phase0-fixture.lock")
                )
            })
    );
    fs::remove_dir_all(&root).expect("remove isolated fixture store");
}

#[test]
fn phase_zero_fixture_store_child_reopens_completed_snapshot() {
    const CHILD_SNAPSHOT: &str = "MSGRIVER_PHASE0_CHILD_SNAPSHOT";
    if let Some(snapshot) = std::env::var_os(CHILD_SNAPSHOT) {
        let reopened = FixtureKernel::reopen_store(Path::new(&snapshot))
            .expect("child reopens completed snapshot");
        assert_eq!(reopened.durable().revision, 4);
        assert_eq!(reopened.durable().events.len(), 1);
        assert_eq!(
            reopened.durable().events[0].reference.as_str(),
            "event-16",
            "child observes only completed durable state"
        );
        return;
    }

    let root = fixture_store_root();
    let snapshot = root.join("child-state.bin");
    let mut fixture = FixtureKernel::with_store(
        DurableState {
            revision: 3,
            ..DurableState::default()
        },
        &snapshot,
    )
    .expect("initialize fixture store");
    fixture
        .replace_durable_state(
            3,
            DurableState {
                revision: 3,
                events: vec![EvidenceEvent {
                    kind: EventKind::StatusRead,
                    reference: SafeReference::parse("event-16").expect("fixed event reference"),
                    sender_generation: 7,
                    provider_occurred_at: Some(18),
                    receipt_order: 1,
                }],
                ..DurableState::default()
            },
        )
        .expect("persist replacement");
    // nosemgrep: rust.lang.security.current-exe.current-exe -- invokes this test binary's ignored child only.
    let executable = std::env::current_exe().expect("locate test executable");
    let status = std::process::Command::new(executable)
        .arg("--exact")
        .arg("phase_zero_reference_loop_fixture::phase_zero_fixture_store_child_reopens_completed_snapshot")
        .arg("--nocapture")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("inherit test path"))
        .env(CHILD_SNAPSHOT, &snapshot)
        .status()
        .expect("launch fixture child");
    assert!(status.success(), "child must reopen the completed snapshot");
    fs::remove_dir_all(&root).expect("remove isolated fixture store");
}

#[test]
fn phase_zero_fixture_process_lock_does_not_survive_worker_termination() {
    const CHILD_SNAPSHOT: &str = "MSGRIVER_PHASE0_LOCKED_SNAPSHOT";
    if let Some(snapshot) = std::env::var_os(CHILD_SNAPSHOT) {
        let (store, _) = FixtureStore::reopen(PathBuf::from(snapshot))
            .expect("child opens durable fixture before locking it");
        let _lock = store
            .acquire_lock()
            .expect("child owns the process-scoped fixture lock");
        std::process::exit(93);
    }

    let root = fixture_store_root();
    let snapshot = root.join("process-lock-state.bin");
    let mut fixture = FixtureKernel::with_store(DurableState::default(), &snapshot)
        .expect("initialize durable fixture before child lock");
    let (store, _) = FixtureStore::reopen(snapshot.clone())
        .expect("parent opens the lock's one durable store domain");
    let lock_path = store.lock_path().expect("derive the durable lock pathname");
    let seed_lock = store
        .acquire_lock()
        .expect("create the persistent lock inode");
    #[cfg(unix)]
    let lock_inode = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(&lock_path)
            .expect("stat initial lock inode")
            .ino()
    };
    drop(seed_lock);
    // nosemgrep: rust.lang.security.current-exe.current-exe -- invokes this test binary's controlled child only.
    let executable = std::env::current_exe().expect("locate test executable");
    let status = std::process::Command::new(executable)
        .arg("--exact")
        .arg("phase_zero_reference_loop_fixture::phase_zero_fixture_process_lock_does_not_survive_worker_termination")
        .arg("--nocapture")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("inherit test path"))
        .env(CHILD_SNAPSHOT, &snapshot)
        .status()
        .expect("launch lock-owning child");
    assert_eq!(status.code(), Some(93), "child dies while owning its lock");
    let successor_lock = store
        .acquire_lock()
        .expect("same lock domain is acquirable after the child dies");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(&lock_path)
                .expect("stat successor lock inode")
                .ino(),
            lock_inode,
            "recovery uses the original lock inode rather than a second lock domain"
        );
    }
    drop(successor_lock);
    fixture
        .replace_durable_state(0, DurableState::default())
        .expect("kernel releases the terminated child's fixture lock");
    assert_eq!(fixture.durable().revision, 1);
    fs::remove_dir_all(&root).expect("remove isolated fixture store");
}

#[test]
fn phase_zero_fixture_lock_domain_is_scoped_to_one_snapshot() {
    let root = fixture_store_root();
    let first_snapshot = root.join("r09-durable-state.bin");
    let second_snapshot = root.join("dispatch-durable-state.bin");
    let first = FixtureKernel::with_store(DurableState::default(), &first_snapshot)
        .expect("initialize first independent snapshot");
    let second = FixtureKernel::with_store(DurableState::default(), &second_snapshot)
        .expect("initialize second independent snapshot");
    let first_store = first.store.as_ref().expect("first store exists");
    let second_store = second.store.as_ref().expect("second store exists");
    assert_ne!(
        first_store.lock_path().expect("first lock path"),
        second_store.lock_path().expect("second lock path"),
        "unrelated R09/R10/R20 snapshots cannot contend on one global lock"
    );
    let first_lock = first_store
        .acquire_lock()
        .expect("acquire first lock domain");
    let second_lock = second_store
        .acquire_lock()
        .expect("independent snapshot remains writable while first is locked");
    drop(second_lock);
    drop(first_lock);
    fs::remove_dir_all(&root).expect("remove isolated fixture store");
}

#[test]
fn phase_zero_fixture_child_termination_preserves_postcommit_snapshot() {
    const CHILD_SNAPSHOT: &str = "MSGRIVER_PHASE0_ABORT_SNAPSHOT";
    if let Some(snapshot) = std::env::var_os(CHILD_SNAPSHOT) {
        let mut fixture = FixtureKernel::reopen_store(Path::new(&snapshot))
            .expect("child reopens initial durable snapshot");
        fixture.inject_stop(TransactionCheckpoint::AfterCommitBeforeAck);
        let result = fixture.replace_durable_state(
            4,
            DurableState {
                revision: 4,
                receipts: vec![Receipt {
                    callback_key: [0x24; 32],
                    sender_generation: 7,
                    kind: CandidateKind::InboundMessage,
                    received_at: 18,
                }],
                events: vec![EvidenceEvent {
                    kind: EventKind::MatchedReply,
                    reference: SafeReference::parse("event-17").expect("fixed event reference"),
                    sender_generation: 7,
                    provider_occurred_at: Some(18),
                    receipt_order: 1,
                }],
                ..DurableState::default()
            },
        );
        assert_eq!(
            result,
            Err(RuntimeError::Stop(RuntimeStop::AfterCommitBeforeAck))
        );
        std::process::exit(93);
    }

    let root = fixture_store_root();
    let snapshot = root.join("postcommit-abort-state.bin");
    let _fixture = FixtureKernel::with_store(
        DurableState {
            revision: 4,
            ..DurableState::default()
        },
        &snapshot,
    )
    .expect("initialize child-abort fixture store");
    // nosemgrep: rust.lang.security.current-exe.current-exe -- invokes this test binary's ignored child only.
    let executable = std::env::current_exe().expect("locate test executable");
    let status = std::process::Command::new(executable)
        .arg("--exact")
        .arg("phase_zero_reference_loop_fixture::phase_zero_fixture_child_termination_preserves_postcommit_snapshot")
        .arg("--nocapture")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("inherit test path"))
        .env(CHILD_SNAPSHOT, &snapshot)
        .status()
        .expect("launch fixture child");
    assert_eq!(
        status.code(),
        Some(93),
        "child terminates after durable barrier"
    );
    let restarted = FixtureKernel::reopen_store(&snapshot).expect("reopen postcommit snapshot");
    assert_eq!(restarted.durable().revision, 5);
    assert_eq!(restarted.durable().receipts.len(), 1);
    assert_eq!(restarted.durable().events[0].reference.as_str(), "event-17");
    fs::remove_dir_all(&root).expect("remove isolated fixture store");
}

#[test]
fn phase_zero_fixture_precommit_stops_preserve_previous_durable_state() {
    let mut fixture = FixtureKernel::with_durable(DurableState {
        revision: 7,
        ..DurableState::default()
    });
    let before = fixture.durable_state();
    fixture.inject_stop(TransactionCheckpoint::BeforeCommit);
    let result = fixture.replace_durable_state(
        7,
        DurableState {
            revision: 7,
            v1_history: vec![V1Fact::ProviderAccepted {
                attempts: 1,
                uncertain: false,
            }],
            ..DurableState::default()
        },
    );
    assert_eq!(result, Err(RuntimeError::Stop(RuntimeStop::BeforeCommit)));
    assert_eq!(fixture.durable(), &before);
}

#[test]
fn phase_zero_fixture_after_receipt_insert_stop_rolls_back_entire_candidate_batch() {
    let mut fixture = FixtureKernel::with_durable(DurableState {
        revision: 8,
        ..DurableState::default()
    });
    let first = Receipt {
        callback_key: [0x12; 32],
        sender_generation: 7,
        kind: CandidateKind::OutboundStatus,
        received_at: 18,
    };
    let second = Receipt {
        callback_key: [0x13; 32],
        sender_generation: 7,
        kind: CandidateKind::InboundMessage,
        received_at: 18,
    };
    fixture
        .stage_callback_candidates(&[first.clone(), second.clone()])
        .expect("stage the literal candidate batch before its transaction barrier");
    fixture.inject_stop(TransactionCheckpoint::AfterReceiptInsert);
    let result = fixture.replace_durable_state(
        8,
        DurableState {
            revision: 8,
            receipts: vec![first, second],
            ..DurableState::default()
        },
    );
    assert_eq!(
        result,
        Err(RuntimeError::Stop(RuntimeStop::AfterReceiptInsert))
    );
    assert!(fixture.durable().receipts.is_empty());
    assert!(fixture.durable().events.is_empty());
    assert_eq!(fixture.durable().revision, 8);
    assert_eq!(
        fixture.staged_candidates().len(),
        2,
        "the stop occurs only after the complete literal receipt delta is validated"
    );
    let restarted = fixture.restart();
    assert!(
        restarted.staged_candidates().is_empty(),
        "a terminated pre-commit transaction leaves no staged receipt durable"
    );
}

#[test]
fn phase_zero_fixture_staged_batch_must_commit_as_one_replacement() {
    let prior = Receipt {
        callback_key: [0x31; 32],
        sender_generation: 7,
        kind: CandidateKind::InboundMessage,
        received_at: 18,
    };
    let staged = Receipt {
        callback_key: [0x32; 32],
        sender_generation: 7,
        kind: CandidateKind::OutboundStatus,
        received_at: 18,
    };
    let extra = Receipt {
        callback_key: [0x33; 32],
        sender_generation: 7,
        kind: CandidateKind::InboundMessage,
        received_at: 18,
    };
    let mut fixture = FixtureKernel::with_durable(DurableState {
        receipts: vec![prior.clone()],
        revision: 1,
        ..DurableState::default()
    });
    fixture
        .stage_callback_candidates(&[staged.clone(), staged.clone()])
        .expect("stage a multiplicity-preserving callback batch");
    assert_eq!(
        fixture.replace_durable_state(
            1,
            DurableState {
                receipts: vec![prior.clone(), staged.clone()],
                ..DurableState::default()
            },
        ),
        Err(RuntimeError::InvalidFixture),
        "a replacement cannot omit one duplicated staged receipt"
    );
    assert_eq!(
        fixture.replace_durable_state(
            1,
            DurableState {
                receipts: vec![staged.clone(), staged.clone()],
                ..DurableState::default()
            },
        ),
        Err(RuntimeError::InvalidFixture),
        "a previously committed receipt cannot impersonate the staged delta"
    );
    assert_eq!(
        fixture.replace_durable_state(
            1,
            DurableState {
                receipts: vec![prior.clone(), staged.clone(), staged.clone(), extra],
                ..DurableState::default()
            },
        ),
        Err(RuntimeError::InvalidFixture),
        "a replacement cannot append an unstaged receipt"
    );
    fixture
        .replace_durable_state(
            1,
            DurableState {
                receipts: vec![prior, staged.clone(), staged],
                ..DurableState::default()
            },
        )
        .expect("the full staged batch commits atomically");
    assert!(fixture.staged_candidates().is_empty());
    assert_eq!(fixture.durable().receipts.len(), 3);
}

#[test]
fn phase_zero_fixture_replacement_cannot_synthesize_a_receipt_stage_stop() {
    let receipt = Receipt {
        callback_key: [0x21; 32],
        sender_generation: 7,
        kind: CandidateKind::InboundMessage,
        received_at: 21,
    };
    let mut fixture = FixtureKernel::with_durable(DurableState {
        revision: 9,
        receipts: vec![receipt.clone(), receipt.clone()],
        ..DurableState::default()
    });
    fixture.inject_stop(TransactionCheckpoint::AfterReceiptInsert);
    let result = fixture.replace_durable_state(
        9,
        DurableState {
            revision: 9,
            receipts: vec![
                receipt,
                Receipt {
                    callback_key: [0x22; 32],
                    sender_generation: 7,
                    kind: CandidateKind::InboundMessage,
                    received_at: 22,
                },
                Receipt {
                    callback_key: [0x23; 32],
                    sender_generation: 7,
                    kind: CandidateKind::InboundMessage,
                    received_at: 23,
                },
            ],
            ..DurableState::default()
        },
    );
    assert_eq!(result, Ok(()));
    assert_eq!(fixture.durable().receipts.len(), 3);
    assert_eq!(fixture.durable().revision, 10);
}

#[test]
fn phase_zero_fixture_postcommit_stop_retains_complete_replacement_after_restart() {
    let mut fixture = FixtureKernel::with_durable(DurableState {
        revision: 4,
        ..DurableState::default()
    });
    fixture.inject_stop(TransactionCheckpoint::AfterCommitBeforeAck);
    let result = fixture.replace_durable_state(
        4,
        DurableState {
            revision: 4,
            receipts: vec![Receipt {
                callback_key: [0x11; 32],
                sender_generation: 7,
                kind: CandidateKind::InboundMessage,
                received_at: 17,
            }],
            bindings: vec![ProviderBinding {
                sender_generation: 7,
                provider_message_id: SafeReference::parse("provider-message-1")
                    .expect("fixed provider reference"),
            }],
            events: vec![EvidenceEvent {
                kind: EventKind::MatchedReply,
                reference: SafeReference::parse("event-1").expect("fixed event reference"),
                sender_generation: 7,
                provider_occurred_at: None,
                receipt_order: 1,
            }],
            tombstones: vec![Tombstone {
                callback_key: [0x11; 32],
                sender_generation: 7,
                key_generation: 3,
            }],
            v1_history: vec![V1Fact::ProviderAccepted {
                attempts: 1,
                uncertain: false,
            }],
            ..DurableState::default()
        },
    );
    assert_eq!(
        result,
        Err(RuntimeError::Stop(RuntimeStop::AfterCommitBeforeAck))
    );
    let restarted = fixture.restart();
    assert_eq!(restarted.durable().revision, 5);
    assert_eq!(
        restarted.durable().v1_history,
        vec![V1Fact::ProviderAccepted {
            attempts: 1,
            uncertain: false,
        }]
    );
    assert_eq!(restarted.durable().receipts.len(), 1);
    assert_eq!(restarted.durable().bindings.len(), 1);
    assert_eq!(restarted.durable().events.len(), 1);
    assert_eq!(restarted.durable().tombstones.len(), 1);
    assert!(restarted.provider_captures().is_empty());
    assert!(restarted.alert_captures().is_empty());
}

#[test]
fn phase_zero_fixture_revision_conflict_cannot_replace_durable_state() {
    let mut fixture = FixtureKernel::with_durable(DurableState {
        revision: 3,
        ..DurableState::default()
    });
    let result = fixture.replace_durable_state(2, DurableState::default());
    assert_eq!(result, Err(RuntimeError::RevisionConflict));
    assert_eq!(fixture.durable().revision, 3);
}

#[test]
fn phase_zero_fixture_dispatch_stop_preserves_typed_safe_capture_only() {
    let event_reference = SafeReference::parse("event-1").expect("fixed safe event reference");
    let mut fixture = FixtureKernel::with_durable(DurableState {
        outbox: vec![crate::phase_zero::reference_loop::AlertIntent {
            event_reference: event_reference.clone(),
            matched: false,
            safe_timestamp: 17,
            leased: false,
            lease_fence: 0,
            lease_expires_at: None,
            dispatch_attempts: 0,
            delivered: false,
            ambiguous_dispatch: false,
        }],
        ..DurableState::default()
    });
    let lease = fixture
        .lease_alert(&event_reference, 17)
        .expect("fixture acquires its initial lease");
    fixture.inject_stop(TransactionCheckpoint::AfterDispatchSend);
    let result = fixture.capture_alert(
        AlertCapture::new(event_reference.clone(), false, 17),
        lease.lease_fence,
        17,
    );
    assert_eq!(
        result,
        Err(RuntimeError::Stop(RuntimeStop::AfterDispatchSend))
    );
    assert_eq!(
        fixture.alert_captures(),
        &[AlertCapture::new(event_reference, false, 17)]
    );
    let mut provider = FixtureKernel::default();
    provider
        .capture_provider(ProviderCapture::new(
            RegisteredTemplate::Phase0Notice,
            7,
            Some(
                SafeReference::parse("provider-message-1").expect("fixed safe provider reference"),
            ),
        ))
        .expect("fixture capture succeeds without an injected stop");
    assert_eq!(provider.provider_captures().len(), 1);
}

#[test]
fn phase_zero_fixture_safe_references_reject_body_like_or_control_values() {
    let accepted = SafeReference::parse("provider-message-1").expect("safe identifier");
    assert_eq!(accepted.as_str(), "provider-message-1");
    assert_eq!(
        SafeReference::parse("message"),
        Err(RuntimeError::InvalidFixture)
    );
    assert_eq!(
        SafeReference::parse("alice@example.com"),
        Err(RuntimeError::InvalidFixture)
    );
    assert_eq!(
        SafeReference::parse("+15551234567"),
        Err(RuntimeError::InvalidFixture)
    );
    assert_eq!(
        SafeReference::parse("line\nfeed"),
        Err(RuntimeError::InvalidFixture)
    );
}

#[test]
fn phase_zero_fixture_before_lease_stop_precedes_durable_lease_transition() {
    let event = SafeReference::parse("event-3").expect("fixed event reference");
    let mut fixture = FixtureKernel::with_durable(DurableState {
        outbox: vec![crate::phase_zero::reference_loop::AlertIntent {
            event_reference: event.clone(),
            matched: false,
            safe_timestamp: 19,
            leased: false,
            lease_fence: 0,
            lease_expires_at: None,
            dispatch_attempts: 0,
            delivered: false,
            ambiguous_dispatch: false,
        }],
        ..DurableState::default()
    });
    fixture.inject_stop(TransactionCheckpoint::BeforeDispatchLease);
    assert_eq!(
        fixture.lease_alert(&event, 19),
        Err(RuntimeError::Stop(RuntimeStop::BeforeDispatchLease))
    );
    assert!(!fixture.durable().outbox[0].leased);
    assert_eq!(fixture.durable().revision, 0);
}

#[test]
fn phase_zero_fixture_before_lease_stop_never_masks_an_ineligible_intent() {
    let event = SafeReference::parse("event-4").expect("fixed event reference");
    let mut fixture = FixtureKernel::default();
    fixture.inject_stop(TransactionCheckpoint::BeforeDispatchLease);
    assert_eq!(
        fixture.lease_alert(&event, 19),
        Err(RuntimeError::InvalidFixture)
    );
}

#[test]
fn phase_zero_fixture_expired_lease_fences_a_stale_dispatcher() {
    let event = SafeReference::parse("event-5").expect("fixed event reference");
    let mut fixture = FixtureKernel::with_durable(DurableState {
        outbox: vec![crate::phase_zero::reference_loop::AlertIntent {
            event_reference: event.clone(),
            matched: true,
            safe_timestamp: 17,
            leased: false,
            lease_fence: 0,
            lease_expires_at: None,
            dispatch_attempts: 0,
            delivered: false,
            ambiguous_dispatch: false,
        }],
        revision: 1,
        ..DurableState::default()
    });
    let stale = fixture
        .lease_alert(&event, 17)
        .expect("first dispatcher acquires a lease");
    let current = fixture
        .lease_alert(&event, 77)
        .expect("expired lease is recoverable by a new dispatcher");
    assert_eq!(stale.lease_fence, 1);
    assert_eq!(current.lease_fence, 2);
    assert!(fixture.durable().outbox[0].ambiguous_dispatch);
    assert_eq!(
        fixture.settle_alert(&event, stale.lease_fence),
        Err(RuntimeError::InvalidFixture)
    );
    assert_eq!(
        fixture.capture_alert(
            AlertCapture::new(event.clone(), true, 77),
            stale.lease_fence,
            77,
        ),
        Err(RuntimeError::InvalidFixture)
    );
    assert_eq!(
        fixture.attempted_alert_captures(),
        &[AlertCapture::new(event.clone(), true, 77)],
        "stale dispatch is independently observed even though its fence rejects settlement"
    );
    assert!(
        fixture.alert_captures().is_empty(),
        "the stale attempt is not reported as a successful alert delivery"
    );
    fixture
        .capture_alert(
            AlertCapture::new(event.clone(), true, 77),
            current.lease_fence,
            77,
        )
        .expect("current fenced dispatcher alone can capture its safe alert");
    fixture
        .settle_alert(&event, current.lease_fence)
        .expect("current fenced dispatcher settles once");
    assert!(fixture.durable().outbox[0].delivered);
    assert_eq!(fixture.durable().outbox[0].dispatch_attempts, 2);
    assert_eq!(fixture.durable().revision, 4);
    assert_eq!(fixture.attempted_alert_captures().len(), 2);
    assert_eq!(fixture.alert_captures().len(), 1);
}

#[test]
fn phase_zero_fixture_shared_store_allows_one_competing_lease_and_fences_the_other_worker() {
    let root = fixture_store_root();
    let snapshot = root.join("competing-dispatchers.bin");
    let event = SafeReference::parse("event-6").expect("fixed event reference");
    let initial = DurableState {
        outbox: vec![crate::phase_zero::reference_loop::AlertIntent {
            event_reference: event.clone(),
            matched: true,
            safe_timestamp: 17,
            leased: false,
            lease_fence: 0,
            lease_expires_at: None,
            dispatch_attempts: 0,
            delivered: false,
            ambiguous_dispatch: false,
        }],
        revision: 1,
        ..DurableState::default()
    };
    let mut worker_a = FixtureKernel::with_store(initial, &snapshot)
        .expect("initialize shared durable dispatcher store");
    let mut worker_b = FixtureKernel::reopen_store(&snapshot)
        .expect("second worker opens the same initial durable snapshot");

    let lease_a = worker_a
        .lease_alert(&event, 17)
        .expect("first worker acquires the one lease");
    assert_eq!(lease_a.lease_fence, 1);
    assert_eq!(
        worker_b.lease_alert(&event, 17),
        Err(RuntimeError::InvalidFixture),
        "a stale cached snapshot must reload and lose to the durable lease"
    );

    let lease_b = worker_b
        .lease_alert(&event, 77)
        .expect("second worker recovers only after the first lease expires");
    assert_eq!(lease_b.lease_fence, 2);
    assert_eq!(
        worker_a.capture_alert(
            AlertCapture::new(event.clone(), true, 77),
            lease_a.lease_fence,
            77,
        ),
        Err(RuntimeError::InvalidFixture),
        "the paused stale worker's attempted external dispatch is observable but fenced"
    );
    assert_eq!(worker_a.attempted_alert_captures().len(), 1);
    assert!(worker_a.alert_captures().is_empty());
    worker_b
        .capture_alert(
            AlertCapture::new(event.clone(), true, 77),
            lease_b.lease_fence,
            77,
        )
        .expect("only the current worker can make a successful safe capture");
    worker_b
        .settle_alert(&event, lease_b.lease_fence)
        .expect("current worker settles its fence");
    assert_eq!(
        worker_a.settle_alert(&event, lease_a.lease_fence),
        Err(RuntimeError::InvalidFixture),
        "the old worker cannot settle the newer durable fence"
    );
    let reopened = FixtureKernel::reopen_store(&snapshot)
        .expect("independent observer reopens the shared authoritative state");
    assert_eq!(reopened.durable().revision, 4);
    assert_eq!(reopened.durable().outbox[0].lease_fence, 2);
    assert_eq!(reopened.durable().outbox[0].dispatch_attempts, 2);
    assert!(reopened.durable().outbox[0].ambiguous_dispatch);
    assert!(reopened.durable().outbox[0].delivered);
    fs::remove_dir_all(&root).expect("remove isolated shared dispatcher store");
}

#[test]
fn phase_zero_fixture_store_lock_serializes_capture_and_expired_lease_recovery() {
    let root = fixture_store_root();
    let snapshot = root.join("capture-recovery-lock.bin");
    let event = SafeReference::parse("event-7").expect("fixed event reference");
    let initial = DurableState {
        outbox: vec![crate::phase_zero::reference_loop::AlertIntent {
            event_reference: event.clone(),
            matched: true,
            safe_timestamp: 17,
            leased: true,
            lease_fence: 1,
            lease_expires_at: Some(77),
            dispatch_attempts: 1,
            delivered: false,
            ambiguous_dispatch: false,
        }],
        revision: 2,
        ..DurableState::default()
    };
    let mut capturing = FixtureKernel::with_store(initial, &snapshot)
        .expect("initialize capture worker durable store");
    let mut recovering = FixtureKernel::reopen_store(&snapshot)
        .expect("open independent recovery worker durable store");
    let store = capturing
        .store
        .as_ref()
        .expect("capture worker owns the shared store")
        .clone();
    let held = store
        .acquire_lock()
        .expect("hold the one shared lock domain");
    let capture = AlertCapture::new(event.clone(), true, 17);
    assert_eq!(
        capturing.capture_alert(capture.clone(), 1, 17),
        Err(RuntimeError::RevisionConflict),
        "capture cannot validate or publish while the common store lock is held"
    );
    assert_eq!(
        recovering.lease_alert(&event, 77),
        Err(RuntimeError::RevisionConflict),
        "expired-lease recovery cannot replace state while that same lock is held"
    );
    assert_eq!(
        capturing.attempted_alert_captures(),
        std::slice::from_ref(&capture),
        "a lock-rejected capture still records its attempt before validation"
    );
    drop(held);
    capturing
        .capture_alert(capture, 1, 17)
        .expect("capture obtains the common lock after the conflicting recovery is excluded");
    capturing
        .settle_alert(&event, 1)
        .expect("the fenced capture settles before any recovery can supersede it");
    assert_eq!(
        recovering.lease_alert(&event, 77),
        Err(RuntimeError::InvalidFixture),
        "a later recovery observes delivery rather than recovering a competing lease"
    );
    fs::remove_dir_all(&root).expect("remove isolated capture/recovery store");
}
