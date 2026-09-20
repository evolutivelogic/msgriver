//! Compiled negative controls for the Phase 0B hermetic execution gate.
//!
//! These are never product behavior. The gate runs each test under `strace`
//! and succeeds only when it rejects the observed forbidden syscall.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::TcpListener;

#[test]
fn phase_zero_reference_loop_hermetic_negative_network_control() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("negative control opens socket");
    drop(listener);
}

#[test]
fn phase_zero_reference_loop_hermetic_negative_file_control() {
    let mut file = File::open("/etc/passwd").expect("negative control opens known host file");
    let mut one_byte = [0_u8; 1];
    file.read_exact(&mut one_byte)
        .expect("negative control reads known host file");
}

#[test]
fn phase_zero_reference_loop_hermetic_negative_dependency_write_control() {
    let executable = std::fs::read_link("/proc/self/exe")
        .expect("negative control resolves the running test executable");
    let dependency_metadata = executable.with_extension("d");
    let file = OpenOptions::new()
        .write(true)
        .open(dependency_metadata)
        .expect("negative control opens dependency with write access");
    drop(file);
}
