//! Task 0250 envelope-to-retained-lock composition RED.

#![forbid(unsafe_code)]

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use msgriver::{
    StateOwnerLock,
    bootstrap_envelope::{EnvelopeExpectation, EnvelopeRootAdapter, EnvelopeTrust},
    service_bootstrap::{BootstrapAdapter, BootstrapAdapterError, BootstrapStep},
};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
struct SelectedStateProbe {
    steps: Arc<Mutex<Vec<BootstrapStep>>>,
}

impl BootstrapAdapter for SelectedStateProbe {
    fn run(&mut self, step: BootstrapStep) -> Result<(), BootstrapAdapterError> {
        self.steps.lock().expect("step recording").push(step);
        if step == BootstrapStep::SelectedState {
            Err(BootstrapAdapterError::Failed)
        } else {
            Ok(())
        }
    }
}

struct Layout {
    base: PathBuf,
    parent: PathBuf,
    state_root: PathBuf,
}

impl Layout {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "msgriver-task0250-composition-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
        ));
        let parent = base.join("etc").join("msgriver");
        let state_root = base.join("state");
        fs::create_dir_all(&parent).expect("envelope parent");
        fs::create_dir(&state_root).expect("state root");
        mode(&parent, 0o750);
        mode(&state_root, 0o700);
        let content = format!(
            "version = 1\nstate_root = \"{}\"\nservice_user = \"msgriver\"\ncredential_root = \"/run/credentials/msgriver\"\nsocket_names = []\nresource_ceiling_profile = \"baseline-v1\"\n",
            state_root.display()
        );
        let envelope = parent.join("bootstrap.toml");
        fs::write(&envelope, content).expect("envelope fixture");
        mode(&envelope, 0o640);
        Self {
            base,
            parent,
            state_root,
        }
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn mode(path: &std::path::Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture mode");
}

#[test]
fn accepted_envelope_reaches_only_selected_state_with_released_retained_lock() {
    let layout = Layout::new();
    let metadata = fs::metadata(&layout.parent).expect("parent metadata");
    let state_root = layout.state_root.to_string_lossy();
    let expectation = EnvelopeExpectation {
        state_root: &state_root,
        service_user: "msgriver",
        credential_root: "/run/credentials/msgriver",
        resource_ceiling_profile: "baseline-v1",
    };
    let steps = Arc::new(Mutex::new(Vec::new()));
    let mut adapter = EnvelopeRootAdapter::new(
        &layout.parent,
        EnvelopeTrust {
            expected_uid: metadata.uid(),
            effective_gid: metadata.gid(),
        },
        expectation,
        SelectedStateProbe {
            steps: Arc::clone(&steps),
        },
    );

    adapter
        .run(BootstrapStep::ProcessPolicy)
        .expect("process policy");
    adapter.run(BootstrapStep::NonRoot).expect("non-root");
    adapter
        .run(BootstrapStep::TrustedRoot)
        .expect("trusted envelope root");
    adapter.run(BootstrapStep::OwnerLock).expect("owner lock");
    assert!(matches!(
        adapter.run(BootstrapStep::SelectedState),
        Err(BootstrapAdapterError::Failed)
    ));
    assert_eq!(
        *steps.lock().expect("read recorded steps"),
        [
            BootstrapStep::ProcessPolicy,
            BootstrapStep::NonRoot,
            BootstrapStep::SelectedState,
        ]
    );
    assert!(
        adapter
            .root_lock()
            .is_some_and(|lock| lock.retains_owner_lock())
    );
    assert!(layout.state_root.join("msgriver.lock").is_file());
    assert!(StateOwnerLock::acquire(&layout.state_root).is_err());
    drop(adapter);
    assert!(StateOwnerLock::acquire(&layout.state_root).is_ok());
    assert!(!layout.state_root.join("selected-state").exists());
    assert!(!layout.state_root.join("store").exists());
}

#[test]
fn refused_envelope_reaches_no_delegate_and_creates_no_lock_or_state_artifact() {
    let layout = Layout::new();
    let envelope = layout.parent.join("bootstrap.toml");
    fs::write(
        &envelope,
        "version = 2\nstate_root = \"/invalid\"\nservice_user = \"msgriver\"\ncredential_root = \"/run/credentials/msgriver\"\nsocket_names = []\nresource_ceiling_profile = \"baseline-v1\"\n",
    )
    .expect("invalid envelope fixture");
    mode(&envelope, 0o640);
    let metadata = fs::metadata(&layout.parent).expect("parent metadata");
    let state_root = layout.state_root.to_string_lossy();
    let expectation = EnvelopeExpectation {
        state_root: &state_root,
        service_user: "msgriver",
        credential_root: "/run/credentials/msgriver",
        resource_ceiling_profile: "baseline-v1",
    };
    let steps = Arc::new(Mutex::new(Vec::new()));
    let mut adapter = EnvelopeRootAdapter::new(
        &layout.parent,
        EnvelopeTrust {
            expected_uid: metadata.uid(),
            effective_gid: metadata.gid(),
        },
        expectation,
        SelectedStateProbe {
            steps: Arc::clone(&steps),
        },
    );

    adapter
        .run(BootstrapStep::ProcessPolicy)
        .expect("process policy");
    adapter.run(BootstrapStep::NonRoot).expect("non-root");
    assert!(matches!(
        adapter.run(BootstrapStep::TrustedRoot),
        Err(BootstrapAdapterError::Failed)
    ));
    assert_eq!(
        *steps.lock().expect("read recorded steps"),
        [BootstrapStep::ProcessPolicy, BootstrapStep::NonRoot]
    );
    assert!(adapter.root_lock().is_none());
    assert!(!layout.state_root.join("msgriver.lock").exists());
    let lock = StateOwnerLock::acquire(&layout.state_root).expect("lock remains available");
    drop(lock);
    assert!(!layout.state_root.join("selected-state").exists());
    assert!(!layout.state_root.join("store").exists());
}
