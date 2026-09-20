//! Task 0250 injected owner/group trust RED.

#![forbid(unsafe_code)]

use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use msgriver::bootstrap_envelope::{
    BootstrapEnvelopeError, ENVELOPE_MAX_LEN, EnvelopeTrust, RELEASE_EXPECTATION,
    read_trusted_envelope,
};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Layout {
    base: PathBuf,
    parent: PathBuf,
}

impl Layout {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "msgriver-task0250-trust-identity-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
        ));
        let parent = base.join("etc/msgriver");
        fs::create_dir_all(&parent).expect("fixture parent");
        mode(&parent, 0o750);
        fs::write(parent.join("bootstrap.toml"), envelope()).expect("fixture envelope");
        mode(&parent.join("bootstrap.toml"), 0o640);
        Self { base, parent }
    }

    fn trust(&self) -> EnvelopeTrust {
        let metadata = fs::metadata(&self.parent).expect("fixture metadata");
        EnvelopeTrust {
            expected_uid: metadata.uid(),
            effective_gid: metadata.gid(),
        }
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn envelope() -> &'static str {
    concat!(
        "version = 1\nstate_root = \"/srv/msgriver/data\"\nservice_user = \"msgriver\"\n",
        "credential_root = \"/run/credentials/msgriver\"\nsocket_names = []\n",
        "resource_ceiling_profile = \"baseline-v1\"\n",
    )
}

fn mode(path: &std::path::Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture mode");
}

#[test]
fn wrong_injected_parent_owner_and_group_are_refused() {
    let layout = Layout::new();
    let trust = layout.trust();
    for (label, invalid) in [
        (
            "owner",
            EnvelopeTrust {
                expected_uid: trust.expected_uid.wrapping_add(1),
                ..trust
            },
        ),
        (
            "group",
            EnvelopeTrust {
                effective_gid: trust.effective_gid.wrapping_add(1),
                ..trust
            },
        ),
    ] {
        assert_eq!(
            read_trusted_envelope(&layout.parent, invalid, RELEASE_EXPECTATION),
            Err(BootstrapEnvelopeError::UntrustedParent),
            "wrong injected parent {label} must be refused"
        );
    }
}

#[test]
fn exact_4096_byte_trusted_file_is_accepted() {
    let layout = Layout::new();
    let envelope_path = layout.parent.join("bootstrap.toml");
    let mut padded = envelope().to_owned();
    padded.push_str(&"#".repeat(ENVELOPE_MAX_LEN - padded.len()));
    assert_eq!(padded.len(), ENVELOPE_MAX_LEN);
    fs::write(&envelope_path, padded).expect("exact-size envelope");
    mode(&envelope_path, 0o640);
    let accepted = read_trusted_envelope(&layout.parent, layout.trust(), RELEASE_EXPECTATION)
        .expect("exact-size trusted envelope must be accepted");
    assert_eq!(
        accepted.state_root().to_string_lossy(),
        "/srv/msgriver/data"
    );
}
