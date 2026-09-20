//! Additive Task 0009 successor: successful ordering retains adapter ownership.

#![forbid(unsafe_code)]

use msgriver::service_bootstrap::{
    BootstrapAdapter, BootstrapAdapterError, BootstrapStep, bootstrap_owned,
};

#[derive(Default)]
struct Probe {
    calls: usize,
}

impl BootstrapAdapter for Probe {
    fn run(&mut self, _step: BootstrapStep) -> Result<(), BootstrapAdapterError> {
        self.calls += 1;
        Ok(())
    }
}

#[test]
fn successful_bootstrap_retains_the_adapter_without_readiness() {
    let runtime = bootstrap_owned(Probe::default()).expect("successor contract");
    assert_eq!(runtime.adapter().calls, 8);
}
