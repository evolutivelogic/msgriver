use super::harness::{CompareResult, Oracle, TestCaseError, case, outcome};
use msgriver_core::Frontier;
use msgriver_core::fence::{
    NormalizedProviderOutcome, ProviderResponseEvidence, classify_provider_response,
};
use msgriver_core::retry::{RetryDisposition, retry_disposition};

const PROVIDER_ROWS: [(ProviderResponseEvidence, NormalizedProviderOutcome); 6] = [
    (
        ProviderResponseEvidence::Accepted,
        NormalizedProviderOutcome::Accepted,
    ),
    (
        ProviderResponseEvidence::Transient,
        NormalizedProviderOutcome::Transient,
    ),
    (
        ProviderResponseEvidence::RateLimited,
        NormalizedProviderOutcome::RateLimited,
    ),
    (
        ProviderResponseEvidence::PermanentValidation,
        NormalizedProviderOutcome::Permanent,
    ),
    (
        ProviderResponseEvidence::AuthenticationConfiguration,
        NormalizedProviderOutcome::AuthenticationConfiguration,
    ),
    (
        ProviderResponseEvidence::Ambiguous,
        NormalizedProviderOutcome::Ambiguous,
    ),
];

const RETRY_ROWS: [(NormalizedProviderOutcome, RetryDisposition); 6] = [
    (
        NormalizedProviderOutcome::Accepted,
        RetryDisposition::NotRetryable,
    ),
    (
        NormalizedProviderOutcome::Transient,
        RetryDisposition::RetryEligible,
    ),
    (
        NormalizedProviderOutcome::RateLimited,
        RetryDisposition::RetryEligible,
    ),
    (
        NormalizedProviderOutcome::Permanent,
        RetryDisposition::NotRetryable,
    ),
    (
        NormalizedProviderOutcome::AuthenticationConfiguration,
        RetryDisposition::CircuitProbe,
    ),
    (
        NormalizedProviderOutcome::Ambiguous,
        RetryDisposition::RetryEligible,
    ),
];

fn provider_matrix(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    for (evidence, expected) in PROVIDER_ROWS {
        match outcome(classify_provider_response(evidence), oracle, |actual| {
            *actual == expected
        })? {
            CompareResult::Pass => {}
            other => return Ok(other),
        }
    }
    Ok(CompareResult::Pass)
}

fn retry_matrix(oracle: &Oracle) -> Result<CompareResult, TestCaseError> {
    for (outcome_value, expected) in RETRY_ROWS {
        match outcome(retry_disposition(outcome_value), oracle, |actual| {
            *actual == expected
        })? {
            CompareResult::Pass => {}
            other => return Ok(other),
        }
    }
    Ok(CompareResult::Pass)
}

#[test]
fn core_s11_classify_provider_matrix() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-CLASSIFY-PROVIDER-MATRIX",
        "tests/fixtures/oracles/core/core-s11-classify-provider-matrix.txt",
        "044985ae0e61a9b7620674703ba4452cc7d3d6cdd0211f1cc078ea73e6f64321",
        Frontier::FenceArbitrate,
        provider_matrix,
    )
}

#[test]
fn core_s11_retry_permanent_stop() -> Result<(), TestCaseError> {
    case(
        "CORE-S11-RETRY-PERMANENT-STOP",
        "tests/fixtures/oracles/core/core-s11-retry-permanent-stop.txt",
        "6e3e5d24cc988e6c5658104bc12800b9a108d0ec89bd7dee666af84f6f2ef5c7",
        Frontier::ComputeBackoff,
        retry_matrix,
    )
}
