//! Additive Task 0009 successor: ordered, injected bootstrap only.

#![forbid(unsafe_code)]

use msgriver::service_bootstrap::{
    BOOTSTRAP_ORDER, BootstrapAdapter, BootstrapAdapterError, BootstrapError, BootstrapStep,
    bootstrap_with,
};

const STEPS: [BootstrapStep; 8] = BOOTSTRAP_ORDER;

struct Probe {
    steps: Vec<BootstrapStep>,
    fail_at: Option<BootstrapStep>,
}

impl BootstrapAdapter for Probe {
    fn run(&mut self, step: BootstrapStep) -> Result<(), BootstrapAdapterError> {
        self.steps.push(step);
        if self.fail_at == Some(step) {
            Err(BootstrapAdapterError::Failed)
        } else {
            Ok(())
        }
    }
}

#[test]
fn runs_every_prerequisite_in_the_reviewed_order() {
    let mut probe = Probe {
        steps: Vec::new(),
        fail_at: None,
    };
    assert!(bootstrap_with(&mut probe).is_ok());
    assert_eq!(probe.steps, STEPS);
}

#[test]
fn first_failed_prerequisite_stops_the_sequence() {
    let mut probe = Probe {
        steps: Vec::new(),
        fail_at: Some(BootstrapStep::Store),
    };
    assert_eq!(bootstrap_with(&mut probe), Err(BootstrapError::Rejected));
    assert_eq!(probe.steps, STEPS[..6]);
}
