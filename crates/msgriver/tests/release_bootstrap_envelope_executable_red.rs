//! Task 0250 release-only executable-envelope contract.

#![forbid(unsafe_code)]

use std::{
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

const NON_READY_DIAGNOSTIC: &str =
    "msgriver: bootstrap selected state is unavailable; service is not ready.\n";
const NON_READY_EXIT: i32 = 78;

struct Decoys {
    base: PathBuf,
    cwd: PathBuf,
    home: PathBuf,
    xdg: PathBuf,
    root: PathBuf,
}

impl Decoys {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "msgriver-task0250-release-envelope-{}",
            std::process::id()
        ));
        let cwd = base.join("cwd");
        let home = base.join("home");
        let xdg = base.join("xdg");
        let root = base.join("root");
        for path in [&cwd, &home, &xdg, &root] {
            fs::create_dir_all(path).expect("decoy root");
            mode(path, 0o700);
        }
        for parent in [
            cwd.join("etc/msgriver"),
            home.join("etc/msgriver"),
            xdg.join("etc/msgriver"),
        ] {
            fs::create_dir_all(&parent).expect("decoy envelope parent");
            mode(&parent, 0o750);
            fs::write(parent.join("bootstrap.toml"), envelope()).expect("decoy envelope");
            mode(&parent.join("bootstrap.toml"), 0o640);
        }
        Self {
            base,
            cwd,
            home,
            xdg,
            root,
        }
    }
}

impl Drop for Decoys {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn envelope() -> &'static str {
    concat!(
        "version = 2\nstate_root = \"/decoy\"\nservice_user = \"msgriver\"\n",
        "credential_root = \"/run/credentials/msgriver\"\nsocket_names = []\n",
        "resource_ceiling_profile = \"baseline-v1\"\n",
    )
}

fn mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture mode");
}

#[test]
#[ignore = "runs only through the Task 0250 release Landlock/strace gate"]
fn release_binary_ignores_decoy_sources_and_retains_static_non_ready_output() {
    let decoys = Decoys::new();
    let output = Command::new(OsString::from(env!("CARGO_BIN_EXE_msgriver")))
        .current_dir(&decoys.cwd)
        .arg(decoys.cwd.join("etc/msgriver/bootstrap.toml"))
        .env("HOME", &decoys.home)
        .env("XDG_CONFIG_HOME", &decoys.xdg)
        .env("MSGRIVER_INTERNAL_BOOTSTRAP_ROOT", &decoys.root)
        .output()
        .expect("start release binary");
    assert_eq!(output.status.code(), Some(NON_READY_EXIT));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        NON_READY_DIAGNOSTIC
    );
    assert!(output.stdout.is_empty());
    for root in [&decoys.cwd, &decoys.home, &decoys.xdg, &decoys.root] {
        assert!(!root.join("msgriver.lock").exists());
        assert!(!root.join("selected-state").exists());
        assert!(!root.join("store").exists());
    }
}
