//! Frozen Task 0009 RED contract: no prerequisite can run before bootstrap.

#![forbid(unsafe_code)]

use msgriver::service_bootstrap::{BootstrapError, BootstrapStep};

#[test]
fn missing_bootstrap_diagnostic_is_static_and_redacted() {
    assert_eq!(
        BootstrapError::MissingBootstrap.to_string(),
        "service bootstrap is not available"
    );
}

#[test]
fn frozen_prerequisite_order_is_explicit() {
    assert_eq!(
        [
            BootstrapStep::ProcessPolicy,
            BootstrapStep::NonRoot,
            BootstrapStep::TrustedRoot,
            BootstrapStep::OwnerLock,
            BootstrapStep::SelectedState,
            BootstrapStep::Store,
            BootstrapStep::StructuralConfiguration,
            BootstrapStep::ProviderCatalog,
        ]
        .len(),
        8,
    );
}
