//! Task 0250 trusted-envelope filesystem RED.

#![forbid(unsafe_code)]

use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt, symlink},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use msgriver::bootstrap_envelope::{
    ENVELOPE_MAX_LEN, EnvelopeExpectation, EnvelopeTrust, RELEASE_EXPECTATION,
    read_trusted_envelope,
};

static NEXT_LAYOUT: AtomicU64 = AtomicU64::new(0);

struct Layout {
    base: PathBuf,
    parent: PathBuf,
}

impl Layout {
    fn valid(label: &str) -> Self {
        let sequence = NEXT_LAYOUT.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "msgriver-task0250-envelope-{label}-{}-{sequence}",
            std::process::id()
        ));
        let parent = base.join("etc").join("msgriver");
        fs::create_dir_all(&parent).expect("fixture parent");
        mode(&parent, 0o750);
        fs::write(parent.join("bootstrap.toml"), golden()).expect("fixture envelope");
        mode(&parent.join("bootstrap.toml"), 0o640);
        Self { base, parent }
    }

    fn trust(&self) -> EnvelopeTrust {
        let metadata = fs::metadata(&self.parent).expect("fixture parent metadata");
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

fn golden() -> &'static str {
    concat!(
        "version = 1\n",
        "state_root = \"/srv/msgriver/data\"\n",
        "service_user = \"msgriver\"\n",
        "credential_root = \"/run/credentials/msgriver\"\n",
        "socket_names = []\n",
        "resource_ceiling_profile = \"baseline-v1\"\n",
    )
}

fn expectation() -> EnvelopeExpectation<'static> {
    RELEASE_EXPECTATION
}

fn mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture mode");
}

fn require_refused(layout: &Layout, label: &str) {
    assert!(
        read_trusted_envelope(&layout.parent, layout.trust(), expectation()).is_err(),
        "{label} must fail closed"
    );
    assert!(
        !layout.parent.join("msgriver.lock").exists(),
        "{label} must not create an owner lock"
    );
}

#[test]
fn valid_exact_owner_group_mode_and_size_are_accepted() {
    let layout = Layout::valid("valid");
    let accepted = read_trusted_envelope(&layout.parent, layout.trust(), expectation())
        .expect("valid trusted envelope must be accepted");
    assert_eq!(
        accepted.state_root().to_string_lossy(),
        "/srv/msgriver/data"
    );
}

#[test]
fn missing_and_non_regular_envelopes_are_refused() {
    let missing = Layout::valid("missing");
    fs::remove_file(missing.parent.join("bootstrap.toml")).expect("remove fixture envelope");
    require_refused(&missing, "missing");

    let symlinked = Layout::valid("symlink");
    let target = symlinked.base.join("target");
    fs::write(&target, golden()).expect("symlink target");
    fs::remove_file(symlinked.parent.join("bootstrap.toml")).expect("remove fixture envelope");
    symlink(&target, symlinked.parent.join("bootstrap.toml")).expect("envelope symlink");
    require_refused(&symlinked, "symlink");

    let hard_linked = Layout::valid("hard-link");
    fs::hard_link(
        hard_linked.parent.join("bootstrap.toml"),
        hard_linked.base.join("second-link"),
    )
    .expect("second envelope link");
    require_refused(&hard_linked, "hard-link");

    let directory = Layout::valid("directory");
    fs::remove_file(directory.parent.join("bootstrap.toml")).expect("remove fixture envelope");
    fs::create_dir(directory.parent.join("bootstrap.toml")).expect("envelope directory");
    require_refused(&directory, "directory");

    let socket = Layout::valid("socket");
    fs::remove_file(socket.parent.join("bootstrap.toml")).expect("remove fixture envelope");
    let _listener =
        UnixListener::bind(socket.parent.join("bootstrap.toml")).expect("envelope socket");
    require_refused(&socket, "socket");
}

#[test]
fn wrong_modes_and_oversize_are_refused() {
    for (label, parent_mode, file_mode, extra_bytes) in [
        ("parent-0755", 0o755, 0o640, 0),
        ("parent-0700", 0o700, 0o640, 0),
        ("file-0644", 0o750, 0o644, 0),
        ("file-0660", 0o750, 0o660, 0),
        ("file-0600", 0o750, 0o600, 0),
        ("oversize", 0o750, 0o640, ENVELOPE_MAX_LEN + 1),
    ] {
        let layout = Layout::valid(label);
        mode(&layout.parent, parent_mode);
        let envelope = layout.parent.join("bootstrap.toml");
        mode(&envelope, file_mode);
        if extra_bytes != 0 {
            fs::write(&envelope, "x".repeat(extra_bytes)).expect("oversize envelope");
            mode(&envelope, file_mode);
        }
        require_refused(&layout, label);
    }
}
