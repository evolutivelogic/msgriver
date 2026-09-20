//! Frozen Task 0007 unit contract, included inside the private production module.
//!
//! Synthetic bytes are inspected only while owned, never printed. Real entropy
//! observations contain only role, requested width, and completion/error. The
//! ownership checks are structural tripwires, not freed-memory observations:
//! before-write ownership and all early exits also require production source
//! review once the Missing bodies are replaced (see the retained RED evidence).

use super::*;
use std::error::Error;
use std::mem::needs_drop;
use zeroize::ZeroizeOnDrop;

const JOURNAL: [u8; 32] = *b"journal-integrity-test-sentinel!";
const RESERVATION: [u8; 32] = *b"portable-reserve-test-sentinel!!";
const J: InitializationKeyRole = InitializationKeyRole::JournalIntegrity;
const R: InitializationKeyRole = InitializationKeyRole::PortableReservation;

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    role: InitializationKeyRole,
    width: usize,
    completion: Result<usize, EntropyFailure>,
}

struct Step {
    sample: [u8; 32],
    written: usize,
    completion: Result<usize, EntropyFailure>,
}

impl Step {
    fn complete(sample: [u8; 32]) -> Self {
        Self {
            sample,
            written: 32,
            completion: Ok(32),
        }
    }
}

struct ScriptedEntropy {
    steps: Vec<Step>,
    observations: Vec<Observation>,
}

impl ScriptedEntropy {
    fn new(steps: Vec<Step>) -> Self {
        Self {
            steps,
            observations: Vec::new(),
        }
    }
}

impl InitializationEntropySource for ScriptedEntropy {
    fn acquire(
        &mut self,
        role: InitializationKeyRole,
        destination: &mut [u8; 32],
    ) -> Result<usize, EntropyFailure> {
        let completion = if let Some(step) = self.steps.get(self.observations.len()) {
            destination[..step.written].copy_from_slice(&step.sample[..step.written]);
            step.completion
        } else {
            // A retry is visible in the trace even if it ultimately fails.
            Err(EntropyFailure::Failed)
        };
        self.observations.push(Observation {
            role,
            width: destination.len(),
            completion,
        });
        completion
    }
}

fn observation(
    role: InitializationKeyRole,
    completion: Result<usize, EntropyFailure>,
) -> Observation {
    Observation {
        role,
        width: 32,
        completion,
    }
}

fn require_pair(
    result: Result<InitializationKeyPair, InitializationKeyPairError>,
) -> InitializationKeyPair {
    match result {
        Ok(pair) => pair,
        Err(InitializationKeyPairError::MissingAcquisition) => {
            panic!("MissingAcquisition: initialization_key_pair_acquisition")
        }
        Err(_) => panic!("complete valid samples did not yield an initialization pair"),
    }
}

// These references bind disposal assertions to the actual production fields,
// not a test-owned lookalike, a fake drop counter, or a raw-memory read.
fn require_zeroizing_ownership(pair: &InitializationKeyPair) {
    fn wrapped(_: &Zeroizing<[u8; 32]>) {}
    fn automatic_cleanup<T: ZeroizeOnDrop>() {}
    wrapped(&pair.journal_integrity.0);
    wrapped(&pair.portable_reservation.0);
    automatic_cleanup::<Zeroizing<[u8; 32]>>();
    assert!(needs_drop::<JournalIntegrityKey>());
    assert!(needs_drop::<PortableReservationKey>());
    assert!(needs_drop::<InitializationKeyPair>());
}

fn require_redacted_pair(pair: &InitializationKeyPair) {
    for alternate in [false, true] {
        let (journal, reservation, whole) = if alternate {
            (
                format!("{:#?}", pair.journal_integrity),
                format!("{:#?}", pair.portable_reservation),
                format!("{pair:#?}"),
            )
        } else {
            (
                format!("{:?}", pair.journal_integrity),
                format!("{:?}", pair.portable_reservation),
                format!("{pair:?}"),
            )
        };
        // Boolean assertions prevent a broken formatter printing secret bytes.
        assert!(journal == "JournalIntegrityKey([REDACTED])");
        assert!(reservation == "PortableReservationKey([REDACTED])");
        assert!(whole == "InitializationKeyPair([REDACTED])");
    }
}

fn require_redacted_error(error: InitializationKeyPairError) {
    let (display, debug) = match error {
        InitializationKeyPairError::Entropy(J) => (
            "initialization key entropy failed",
            "Entropy(JournalIntegrity)",
        ),
        InitializationKeyPairError::Entropy(R) => (
            "initialization key entropy failed",
            "Entropy(PortableReservation)",
        ),
        InitializationKeyPairError::Incomplete(J) => (
            "initialization key sample is incomplete",
            "Incomplete(JournalIntegrity)",
        ),
        InitializationKeyPairError::Incomplete(R) => (
            "initialization key sample is incomplete",
            "Incomplete(PortableReservation)",
        ),
        InitializationKeyPairError::Zero(J) => (
            "initialization key sample is zero",
            "Zero(JournalIntegrity)",
        ),
        InitializationKeyPairError::Zero(R) => (
            "initialization key sample is zero",
            "Zero(PortableReservation)",
        ),
        InitializationKeyPairError::Equal => ("initialization key samples are equal", "Equal"),
        InitializationKeyPairError::MissingAcquisition => (
            "initialization key-pair acquisition is not implemented",
            "MissingAcquisition",
        ),
    };
    assert!(error.to_string() == display);
    assert!(format!("{error:?}") == debug);
    assert!(error.source().is_none());
}

fn successful_samples(journal: [u8; 32], reservation: [u8; 32]) {
    let mut source =
        ScriptedEntropy::new(vec![Step::complete(journal), Step::complete(reservation)]);
    let mut continuations = 0;
    let pair = require_pair(
        acquire_initialization_key_pair_with(&mut source).inspect(|_| {
            continuations += 1;
        }),
    );
    assert_eq!(continuations, 1);
    assert_eq!(
        source.observations,
        [observation(J, Ok(32)), observation(R, Ok(32))]
    );
    assert!(*pair.journal_integrity.0 == journal);
    assert!(*pair.portable_reservation.0 == reservation);
    require_zeroizing_ownership(&pair);
    require_redacted_pair(&pair);
    drop(pair);
}

#[test]
fn distinguishable_samples_preserve_bytes_roles_and_dispose_one_pair() {
    successful_samples(JOURNAL, RESERVATION);
}

#[test]
fn swapped_samples_are_preserved_without_hardcoded_role_material() {
    successful_samples(RESERVATION, JOURNAL);
}

#[test]
fn nonzero_means_any_nonzero_byte_including_last_position() {
    let mut journal = [0; 32];
    let mut reservation = [0; 32];
    journal[31] = 1;
    reservation[0] = 1;
    successful_samples(journal, reservation);
}

fn rejected_sample(role: InitializationKeyRole, fault: Step, expected: InitializationKeyPairError) {
    let completion = fault.completion;
    let (steps, observations) = if role == J {
        // A valid second sample is available: first-sample refusal must not draw it.
        (
            vec![fault, Step::complete(RESERVATION)],
            vec![observation(J, completion)],
        )
    } else {
        (
            vec![Step::complete(JOURNAL), fault],
            vec![observation(J, Ok(32)), observation(R, completion)],
        )
    };
    rejected_steps(steps, observations, expected);
}

fn rejected_steps(
    steps: Vec<Step>,
    observations: Vec<Observation>,
    expected: InitializationKeyPairError,
) {
    let mut source = ScriptedEntropy::new(steps);
    let mut continuations = 0;
    let result = acquire_initialization_key_pair_with(&mut source).map(|pair| {
        continuations += 1;
        drop(pair);
    });
    assert_eq!(
        continuations, 0,
        "rejection reached the success continuation"
    );
    let error = match result {
        Err(InitializationKeyPairError::MissingAcquisition) => {
            panic!("MissingAcquisition: initialization_key_pair_acquisition")
        }
        Err(error) => error,
        Ok(()) => panic!("rejection returned a usable pair"),
    };
    // Exact classification rules out a generic failure, wrong position, padding,
    // reuse, fallback, and successful reroll. No error variant can hold a key.
    assert_eq!(error, expected);
    assert_eq!(source.observations, observations);
    require_redacted_error(error);
}

macro_rules! incomplete_cases {
    ($($name:ident: $length:literal),+ $(,)?) => { $(
        #[test]
        fn $name() {
            rejected_sample(ROLE, Step {
                sample: RESERVATION,
                written: $length,
                completion: Ok($length),
            }, InitializationKeyPairError::Incomplete(ROLE));
        }
    )+ };
}

macro_rules! position_cases {
    ($module:ident, $role:expr) => {
        mod $module {
            use super::*;
            const ROLE: InitializationKeyRole = $role;

            incomplete_cases!(
                short_00: 0, short_01: 1, short_02: 2, short_03: 3,
                short_04: 4, short_05: 5, short_06: 6, short_07: 7,
                short_08: 8, short_09: 9, short_10: 10, short_11: 11,
                short_12: 12, short_13: 13, short_14: 14, short_15: 15,
                short_16: 16, short_17: 17, short_18: 18, short_19: 19,
                short_20: 20, short_21: 21, short_22: 22, short_23: 23,
                short_24: 24, short_25: 25, short_26: 26, short_27: 27,
                short_28: 28, short_29: 29, short_30: 30, short_31: 31,
            );

            #[test]
            fn entropy_error_before_write() {
                entropy_error(0);
            }

            #[test]
            fn entropy_error_after_partial_sentinel_write() {
                entropy_error(17);
            }

            #[test]
            fn entropy_error_after_complete_sentinel_write() {
                entropy_error(32);
            }

            fn entropy_error(written: usize) {
                rejected_sample(ROLE, Step {
                    sample: RESERVATION,
                    written,
                    completion: Err(EntropyFailure::Failed),
                }, InitializationKeyPairError::Entropy(ROLE));
            }

            #[test]
            fn complete_zero_sample() {
                rejected_sample(ROLE, Step::complete([0; 32]), InitializationKeyPairError::Zero(ROLE));
            }

            #[test]
            fn zero_count_is_not_repaired_from_written_nonzero_bytes() {
                rejected_sample(ROLE, Step {
                    sample: RESERVATION,
                    written: 32,
                    completion: Ok(0),
                }, InitializationKeyPairError::Incomplete(ROLE));
            }

            #[test]
            fn oversized_count_is_not_a_complete_sample() {
                for count in [33, usize::MAX] {
                    rejected_sample(ROLE, Step {
                        sample: RESERVATION,
                        written: 32,
                        completion: Ok(count),
                    }, InitializationKeyPairError::Incomplete(ROLE));
                }
            }
        }
    };
}

position_cases!(journal_position, J);
position_cases!(reservation_position, R);

#[test]
fn equal_complete_nonzero_samples_are_rejected_without_reroll() {
    rejected_steps(
        vec![Step::complete(JOURNAL), Step::complete(JOURNAL)],
        vec![observation(J, Ok(32)), observation(R, Ok(32))],
        InitializationKeyPairError::Equal,
    );
}

#[test]
fn synthetic_role_sentinels_are_redacted_and_owned_by_automatic_cleanup_types() {
    let pair = InitializationKeyPair {
        journal_integrity: JournalIntegrityKey(Zeroizing::new(JOURNAL)),
        portable_reservation: PortableReservationKey(Zeroizing::new(RESERVATION)),
    };
    require_redacted_pair(&pair);
    require_zeroizing_ownership(&pair);
    drop(pair);
}

#[test]
fn closed_errors_are_static_and_have_no_secret_bearing_source() {
    for role in [J, R] {
        for error in [
            InitializationKeyPairError::Entropy(role),
            InitializationKeyPairError::Incomplete(role),
            InitializationKeyPairError::Zero(role),
        ] {
            require_redacted_error(error);
        }
    }
    require_redacted_error(InitializationKeyPairError::Equal);
    require_redacted_error(InitializationKeyPairError::MissingAcquisition);
    for (error, display, debug) in [
        (
            EntropyFailure::Failed,
            "initialization entropy acquisition failed",
            "Failed",
        ),
        (
            EntropyFailure::MissingOsAdapter,
            "initialization OS entropy adapter is not implemented",
            "MissingOsAdapter",
        ),
    ] {
        assert!(error.to_string() == display);
        assert!(format!("{error:?}") == debug);
        assert!(error.source().is_none());
    }
}

struct ObservedOsEntropy {
    source: OsInitializationEntropy,
    observations: Vec<Observation>,
}

impl InitializationEntropySource for ObservedOsEntropy {
    fn acquire(
        &mut self,
        role: InitializationKeyRole,
        destination: &mut [u8; 32],
    ) -> Result<usize, EntropyFailure> {
        let completion = self.source.acquire(role, destination);
        self.observations.push(observation(role, completion));
        // Record the actual requested width rather than infer it from success.
        if let Some(last) = self.observations.last_mut() {
            last.width = destination.len();
        }
        completion
    }
}

#[test]
fn real_os_adapter_has_two_role_specific_logical_completions() {
    let mut source = ObservedOsEntropy {
        source: OsInitializationEntropy,
        observations: Vec::new(),
    };
    let pair = require_pair(acquire_initialization_key_pair_with(&mut source));
    assert_eq!(
        source.observations,
        [observation(J, Ok(32)), observation(R, Ok(32))]
    );
    require_zeroizing_ownership(&pair);
    require_redacted_pair(&pair);
    drop(pair);
}

#[test]
fn production_entry_acquires_and_disposes_an_unpublished_pair() {
    let pair = require_pair(acquire_initialization_key_pair());
    require_zeroizing_ownership(&pair);
    require_redacted_pair(&pair);
    drop(pair);
}

// Exercise the separate adapter frontier directly so its absence cannot hide
// behind MissingAcquisition in the retained RED run. This is not a syscall count.
#[test]
fn real_os_adapter_journal_request_reaches_its_own_frontier() {
    real_adapter_request(J);
}

#[test]
fn real_os_adapter_reservation_request_reaches_its_own_frontier() {
    real_adapter_request(R);
}

fn real_adapter_request(role: InitializationKeyRole) {
    let mut destination = Zeroizing::new([0; 32]);
    match OsInitializationEntropy.acquire(role, &mut destination) {
        Ok(32) => {}
        Err(EntropyFailure::MissingOsAdapter) => {
            panic!("MissingOsAdapter: initialization_os_entropy")
        }
        _ => panic!("real OS adapter did not complete its logical sample"),
    }
}
