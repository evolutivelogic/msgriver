//! Compiled negative controls for the private deployment-boundary RED gate.
//!
//! They are ignored outside the hermetic runner. Each passes only when its
//! forbidden effect is prevented before completion.

use std::fs::{File, OpenOptions};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

#[test]
#[ignore = "runs only under the deployment hermetic confinement gate"]
fn phase_zero_deployment_hermetic_negative_network_control() {
    // The runner's trace separately requires both initial socket(2) calls to
    // fail. No Internet or Unix-domain bind can run after creation fails.
    assert!(
        TcpListener::bind("127.0.0.1:0").is_err(),
        "runner confinement must reject socket creation before bind/connect"
    );
    let root = std::env::var_os("MSGRIVER_PHASE0_STORE_ROOT")
        .map(PathBuf::from)
        .expect("runner supplies private fixture root");
    assert!(
        UnixListener::bind(root.join("forbidden-unix.sock")).is_err(),
        "runner confinement must reject Unix socket creation before bind"
    );
    println!("negative-control: all socket families prevented before bind");
}

#[test]
#[ignore = "runs only under the deployment hermetic confinement gate"]
fn phase_zero_deployment_hermetic_negative_file_control() {
    assert!(
        File::open("/etc/passwd").is_err(),
        "runner fixture guard must reject host-file read before data is returned"
    );
    println!("negative-control: host-file read prevented before data return");
}

#[test]
#[ignore = "runs only under the deployment hermetic confinement gate"]
fn phase_zero_deployment_hermetic_negative_dependency_write_control() {
    let dependency_metadata = std::env::var("MSGRIVER_PHASE0_DEPENDENCY_TARGET")
        .expect("runner supplies an existing writable dependency target");
    let error = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(dependency_metadata)
        .expect_err("runner confinement must reject dependency write before modification");
    assert!(
        matches!(error.raw_os_error(), Some(1 | 13 | 30)),
        "dependency target must fail through permission/read-only confinement: {error:?}"
    );
    println!("negative-control: dependency write prevented before modification");
}

#[test]
#[ignore = "runs only under the deployment hermetic confinement gate"]
fn phase_zero_deployment_hermetic_negative_truncate_control() {
    // The launcher invokes truncate(2) against the supplied pre-existing host
    // file after it installs Landlock. This test is the named child witness;
    // the runner also checks the syscall denial and unchanged file hash.
    println!("negative-control: direct truncate prevented before modification");
}
