//! Task 0250 bootstrap-envelope parser and trusted-reader seam.
//!
//! It accepts no configuration source. The trusted reader confines its only
//! filesystem access to the fixed basename beneath a caller-supplied absolute
//! parent descriptor, then exposes only the accepted state root.

use std::{
    ffi::CString,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::service_bootstrap::{
    BootstrapAdapter, BootstrapAdapterError, BootstrapStep, RootLockAdapter,
};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use toml_edit::DocumentMut;

/// The sole release parent pathname; callers cannot substitute it.
#[doc(hidden)]
pub const RELEASE_ENVELOPE_PARENT: &str = "/etc/msgriver";
/// The sole release envelope basename; callers cannot substitute it.
#[doc(hidden)]
pub const RELEASE_ENVELOPE_NAME: &str = "bootstrap.toml";
/// The maximum accepted envelope byte length.
#[doc(hidden)]
pub const ENVELOPE_MAX_LEN: usize = 4096;

/// Closed literals compiled into the release composition root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct EnvelopeExpectation<'a> {
    pub state_root: &'a str,
    pub service_user: &'a str,
    pub credential_root: &'a str,
    pub resource_ceiling_profile: &'a str,
}

/// The release executable has no injectable bootstrap source.
#[doc(hidden)]
pub const RELEASE_EXPECTATION: EnvelopeExpectation<'static> = EnvelopeExpectation {
    state_root: "/srv/msgriver/data",
    service_user: "msgriver",
    credential_root: "/run/credentials/msgriver",
    resource_ceiling_profile: "baseline-v1",
};

/// Injectable identity values for hermetic library contracts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct EnvelopeTrust {
    pub expected_uid: u32,
    pub effective_gid: u32,
}

/// Fieldless failures ensure no path, value or parser diagnostic escapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum BootstrapEnvelopeError {
    Missing,
    UntrustedParent,
    UntrustedFile,
    Replaced,
    Oversized,
    Malformed,
    Rejected,
}

/// Parsed data exposes only the fixed state root to later bootstrap work.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct BootstrapEnvelopeV1 {
    state_root: PathBuf,
}

impl BootstrapEnvelopeV1 {
    #[doc(hidden)]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }
}

/// Parse the closed v1 document without touching the filesystem.
///
/// The grammar parser handles TOML's decoded-key and duplicate-key semantics;
/// this boundary then accepts only the six literal v1 values. Its error is
/// intentionally fieldless, so untrusted document text cannot reach diagnostics.
#[doc(hidden)]
pub fn parse_envelope_v1(
    bytes: &[u8],
    expectation: EnvelopeExpectation<'_>,
) -> Result<BootstrapEnvelopeV1, BootstrapEnvelopeError> {
    if bytes.len() > ENVELOPE_MAX_LEN {
        return Err(BootstrapEnvelopeError::Oversized);
    }
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) || bytes.contains(&0) {
        return Err(BootstrapEnvelopeError::Malformed);
    }
    let source = std::str::from_utf8(bytes).map_err(|_| BootstrapEnvelopeError::Malformed)?;
    let document = DocumentMut::from_str(source).map_err(|_| BootstrapEnvelopeError::Malformed)?;
    let table = document.as_table();
    if table.len() != 6
        || table.get("version").and_then(|item| item.as_integer()) != Some(1)
        || table.get("state_root").and_then(|item| item.as_str()) != Some(expectation.state_root)
        || table.get("service_user").and_then(|item| item.as_str())
            != Some(expectation.service_user)
        || table.get("credential_root").and_then(|item| item.as_str())
            != Some(expectation.credential_root)
        || table
            .get("resource_ceiling_profile")
            .and_then(|item| item.as_str())
            != Some(expectation.resource_ceiling_profile)
        || !table
            .get("socket_names")
            .and_then(|item| item.as_array())
            .is_some_and(|array| array.is_empty())
        || ![
            "version",
            "state_root",
            "service_user",
            "credential_root",
            "socket_names",
            "resource_ceiling_profile",
        ]
        .into_iter()
        .all(|key| table.get(key).is_some_and(|item| item.is_value()))
    {
        return Err(BootstrapEnvelopeError::Malformed);
    }
    Ok(BootstrapEnvelopeV1 {
        state_root: PathBuf::from(expectation.state_root),
    })
}

/// Read one trusted envelope relative to its supplied parent.
///
/// This reader owns the exact no-follow identity race protocol; no alternate
/// source belongs in this seam.
#[doc(hidden)]
pub fn read_trusted_envelope(
    parent: &Path,
    trust: EnvelopeTrust,
    expectation: EnvelopeExpectation<'_>,
) -> Result<BootstrapEnvelopeV1, BootstrapEnvelopeError> {
    if !parent.is_absolute() {
        return Err(BootstrapEnvelopeError::UntrustedParent);
    }
    let parent_name = CString::new(parent.as_os_str().as_bytes())
        .map_err(|_| BootstrapEnvelopeError::UntrustedParent)?;
    let directory = rustix::fs::openat(
        rustix::fs::CWD,
        parent_name.as_c_str(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BootstrapEnvelopeError::UntrustedParent)?;
    let parent_stat =
        rustix::fs::fstat(&directory).map_err(|_| BootstrapEnvelopeError::UntrustedParent)?;
    if FileType::from_raw_mode(parent_stat.st_mode) != FileType::Directory
        || parent_stat.st_mode & 0o7777 != 0o750
        || parent_stat.st_uid != trust.expected_uid
        || parent_stat.st_gid != trust.effective_gid
    {
        return Err(BootstrapEnvelopeError::UntrustedParent);
    }
    let before = envelope_stat(&directory)?;
    validate_envelope_stat(&before, trust)?;
    if before.st_size > ENVELOPE_MAX_LEN as _ {
        return Err(BootstrapEnvelopeError::Oversized);
    }
    let file = rustix::fs::openat(
        &directory,
        RELEASE_ENVELOPE_NAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| BootstrapEnvelopeError::UntrustedFile)?;
    let opened = rustix::fs::fstat(&file).map_err(|_| BootstrapEnvelopeError::UntrustedFile)?;
    validate_envelope_stat(&opened, trust)?;
    if !same_envelope_identity(&before, &opened) {
        return Err(BootstrapEnvelopeError::Replaced);
    }
    let mut bytes = Vec::with_capacity(ENVELOPE_MAX_LEN + 1);
    loop {
        let mut chunk = [0_u8; 1024];
        // Request at most the one-byte oversize discriminator. This makes the
        // kernel read bound itself 4097 bytes, rather than merely rejecting a
        // larger buffer after it was read from an untrusted file.
        let remaining = ENVELOPE_MAX_LEN + 1 - bytes.len();
        let count = rustix::io::read(&file, &mut chunk[..remaining.min(1024)])
            .map_err(|_| BootstrapEnvelopeError::UntrustedFile)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > ENVELOPE_MAX_LEN {
            return Err(BootstrapEnvelopeError::Oversized);
        }
    }
    if bytes.len() > ENVELOPE_MAX_LEN {
        return Err(BootstrapEnvelopeError::Oversized);
    }
    if bytes.len() != opened.st_size as usize {
        return Err(BootstrapEnvelopeError::Replaced);
    }
    let after = envelope_stat(&directory)?;
    validate_envelope_stat(&after, trust)?;
    if !same_envelope_identity(&opened, &after) {
        return Err(BootstrapEnvelopeError::Replaced);
    }
    parse_envelope_v1(&bytes, expectation)
}

fn envelope_stat<Fd: rustix::fd::AsFd>(
    directory: Fd,
) -> Result<rustix::fs::Stat, BootstrapEnvelopeError> {
    rustix::fs::statat(directory, RELEASE_ENVELOPE_NAME, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| BootstrapEnvelopeError::UntrustedFile)
}

fn validate_envelope_stat(
    stat: &rustix::fs::Stat,
    trust: EnvelopeTrust,
) -> Result<(), BootstrapEnvelopeError> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_mode & 0o7777 != 0o640
        || stat.st_uid != trust.expected_uid
        || stat.st_gid != trust.effective_gid
        || stat.st_nlink != 1
        || stat.st_size < 0
    {
        return Err(BootstrapEnvelopeError::UntrustedFile);
    }
    Ok(())
}

fn same_envelope_identity(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_nlink == right.st_nlink
        && left.st_size == right.st_size
}

/// Adapter seam that owns the existing TrustedRoot step without adding one.
///
/// Until the trusted reader exists, it fails at TrustedRoot and never delegates
/// an authority-bearing later step. The future implementation may create the
/// existing RootLockAdapter only after accepting the envelope.
#[doc(hidden)]
pub struct EnvelopeRootAdapter<'a, A> {
    parent: &'a Path,
    trust: EnvelopeTrust,
    expectation: EnvelopeExpectation<'a>,
    delegate: A,
    root_lock: Option<RootLockAdapter>,
    process_policy_applied: bool,
    non_root_confirmed: bool,
    trusted_root: bool,
    owner_lock_acquired: bool,
}

impl<'a, A> EnvelopeRootAdapter<'a, A> {
    #[doc(hidden)]
    pub fn new(
        parent: &'a Path,
        trust: EnvelopeTrust,
        expectation: EnvelopeExpectation<'a>,
        delegate: A,
    ) -> Self {
        Self {
            parent,
            trust,
            expectation,
            delegate,
            root_lock: None,
            process_policy_applied: false,
            non_root_confirmed: false,
            trusted_root: false,
            owner_lock_acquired: false,
        }
    }

    #[doc(hidden)]
    pub fn delegate(&self) -> &A {
        &self.delegate
    }

    #[doc(hidden)]
    pub fn root_lock(&self) -> Option<&RootLockAdapter> {
        self.root_lock.as_ref()
    }
}

impl<A: BootstrapAdapter> BootstrapAdapter for EnvelopeRootAdapter<'_, A> {
    fn run(&mut self, step: BootstrapStep) -> Result<(), BootstrapAdapterError> {
        match step {
            BootstrapStep::ProcessPolicy => {
                if self.process_policy_applied {
                    return Err(BootstrapAdapterError::Failed);
                }
                self.delegate.run(step)?;
                self.process_policy_applied = true;
                Ok(())
            }
            BootstrapStep::NonRoot => {
                if !self.process_policy_applied || self.non_root_confirmed {
                    return Err(BootstrapAdapterError::Failed);
                }
                self.delegate.run(step)?;
                self.non_root_confirmed = true;
                Ok(())
            }
            BootstrapStep::TrustedRoot => {
                if !self.non_root_confirmed || self.trusted_root {
                    return Err(BootstrapAdapterError::Failed);
                }
                let envelope = read_trusted_envelope(self.parent, self.trust, self.expectation)
                    .map_err(|_| BootstrapAdapterError::Failed)?;
                let mut root_lock = RootLockAdapter::new(envelope.state_root());
                root_lock.run_root_step(step)?;
                self.root_lock = Some(root_lock);
                self.trusted_root = true;
                Ok(())
            }
            BootstrapStep::OwnerLock => {
                if !self.trusted_root || self.owner_lock_acquired {
                    return Err(BootstrapAdapterError::Failed);
                }
                self.root_lock
                    .as_mut()
                    .ok_or(BootstrapAdapterError::Failed)?
                    .run_root_step(step)?;
                self.owner_lock_acquired = true;
                Ok(())
            }
            _ => {
                if !self.owner_lock_acquired {
                    return Err(BootstrapAdapterError::Failed);
                }
                self.delegate.run(step)
            }
        }
    }
}
