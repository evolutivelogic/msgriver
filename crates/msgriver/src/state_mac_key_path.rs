//! Task 0096 private state-key relative-path frontier.

#![allow(dead_code)]

use msgriver_core::canon::MacKeyRef;

pub(super) struct StateMacKeyRelativePath(pub(super) [u8; 90]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StateMacKeyRelativePathError {
    MissingStateMacKeyRelativePath,
}

pub(super) fn state_mac_key_relative_path(
    reference: MacKeyRef,
) -> Result<StateMacKeyRelativePath, StateMacKeyRelativePathError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut path = [0; 90];
    path[..4].copy_from_slice(b"mac/");
    let purpose = reference.purpose() as u8;
    path[4] = HEX[usize::from(purpose >> 4)];
    path[5] = HEX[usize::from(purpose & 0x0f)];
    path[6..10].copy_from_slice(b"/mk_");
    for (index, byte) in reference.key_id().as_bytes().iter().enumerate() {
        path[10 + index * 2] = HEX[usize::from(byte >> 4)];
        path[11 + index * 2] = HEX[usize::from(byte & 0x0f)];
    }
    Ok(StateMacKeyRelativePath(path))
}

#[cfg(test)]
#[path = "red_state_mac_key_path.rs"]
mod red_state_mac_key_path;
