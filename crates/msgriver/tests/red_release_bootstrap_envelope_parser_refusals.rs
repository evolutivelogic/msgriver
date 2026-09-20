//! Task 0250 one-mutation parser-refusal RED.

#![forbid(unsafe_code)]

use msgriver::bootstrap_envelope::{
    BootstrapEnvelopeError, ENVELOPE_MAX_LEN, RELEASE_EXPECTATION, parse_envelope_v1,
};

fn golden() -> String {
    concat!(
        "version = 1\n",
        "state_root = \"/srv/msgriver/data\"\n",
        "service_user = \"msgriver\"\n",
        "credential_root = \"/run/credentials/msgriver\"\n",
        "socket_names = []\n",
        "resource_ceiling_profile = \"baseline-v1\"\n",
    )
    .to_owned()
}

fn replace_once(source: &str, old: &str, new: &str) -> Vec<u8> {
    assert_eq!(
        source.matches(old).count(),
        1,
        "fixture mutation must be unique"
    );
    source.replacen(old, new, 1).into_bytes()
}

fn remove_once(source: &str, line: &str) -> Vec<u8> {
    assert_eq!(
        source.matches(line).count(),
        1,
        "fixture removal must be unique"
    );
    source.replacen(line, "", 1).into_bytes()
}

fn require_refusal(label: &str, bytes: &[u8], expected: BootstrapEnvelopeError) {
    assert_eq!(
        parse_envelope_v1(bytes, RELEASE_EXPECTATION),
        Err(expected),
        "{label} must fail with its closed error variant"
    );
}

#[test]
fn one_mutation_values_and_unknown_keys_are_rejected() {
    let base = golden();
    for (label, bytes, expected) in [
        (
            "version-other",
            replace_once(&base, "version = 1", "version = 2"),
            BootstrapEnvelopeError::Malformed,
        ),
        (
            "version-string",
            replace_once(&base, "version = 1", "version = \"1\""),
            BootstrapEnvelopeError::Malformed,
        ),
        (
            "state-relative",
            replace_once(&base, "/srv/msgriver/data", "state"),
            BootstrapEnvelopeError::Malformed,
        ),
        (
            "state-dot",
            replace_once(&base, "/srv/msgriver/data", "/srv/msgriver/../data"),
            BootstrapEnvelopeError::Malformed,
        ),
        (
            "state-trailing",
            replace_once(&base, "/srv/msgriver/data", "/srv/msgriver/data/"),
            BootstrapEnvelopeError::Malformed,
        ),
        (
            "service-user",
            replace_once(
                &base,
                "service_user = \"msgriver\"",
                "service_user = \"other\"",
            ),
            BootstrapEnvelopeError::Malformed,
        ),
        (
            "credential-root",
            replace_once(&base, "/run/credentials/msgriver", "/run/credentials/other"),
            BootstrapEnvelopeError::Malformed,
        ),
        (
            "profile",
            replace_once(&base, "baseline-v1", "other"),
            BootstrapEnvelopeError::Malformed,
        ),
        (
            "socket-member",
            replace_once(&base, "socket_names = []", "socket_names = [\"x\"]"),
            BootstrapEnvelopeError::Malformed,
        ),
        (
            "socket-not-array",
            replace_once(&base, "socket_names = []", "socket_names = \"x\""),
            BootstrapEnvelopeError::Malformed,
        ),
        (
            "unknown",
            format!("{base}unknown = 1\n").into_bytes(),
            BootstrapEnvelopeError::Malformed,
        ),
        (
            "case-unknown",
            format!("{base}Version = 1\n").into_bytes(),
            BootstrapEnvelopeError::Malformed,
        ),
    ] {
        require_refusal(label, &bytes, expected);
    }
}

#[test]
fn duplicate_and_toml_alternate_key_spellings_are_rejected() {
    let base = golden();
    for (label, bytes) in [
        (
            "duplicate-bare",
            format!("{base}version = 1\n").into_bytes(),
        ),
        (
            "duplicate-basic",
            format!("{base}\"state_root\" = \"/srv/msgriver/data\"\n").into_bytes(),
        ),
        (
            "duplicate-literal",
            format!("{base}'state_root' = '/srv/msgriver/data'\n").into_bytes(),
        ),
        (
            "duplicate-escaped",
            format!("{base}\"state\\u005froot\" = \"/srv/msgriver/data\"\n").into_bytes(),
        ),
        ("dotted", format!("{base}socket_names.x = 1\n").into_bytes()),
        ("table", format!("{base}[extra]\nx = 1\n").into_bytes()),
        (
            "inline-table",
            replace_once(&base, "socket_names = []", "socket_names = { x = 1 }"),
        ),
    ] {
        require_refusal(label, &bytes, BootstrapEnvelopeError::Malformed);
    }
}

#[test]
fn incomplete_documents_are_rejected() {
    let base = golden();
    for (label, line) in [
        ("version", "version = 1\n"),
        ("state-root", "state_root = \"/srv/msgriver/data\"\n"),
        ("service-user", "service_user = \"msgriver\"\n"),
        (
            "credential-root",
            "credential_root = \"/run/credentials/msgriver\"\n",
        ),
        ("socket-names", "socket_names = []\n"),
        (
            "resource-profile",
            "resource_ceiling_profile = \"baseline-v1\"\n",
        ),
    ] {
        require_refusal(
            label,
            &remove_once(&base, line),
            BootstrapEnvelopeError::Malformed,
        );
    }
    require_refusal("empty", b"", BootstrapEnvelopeError::Malformed);
}

#[test]
fn malformed_encoding_and_oversize_are_rejected() {
    let mut bom = b"\xef\xbb\xbf".to_vec();
    bom.extend(golden().as_bytes());
    require_refusal("bom", &bom, BootstrapEnvelopeError::Malformed);
    require_refusal(
        "invalid-utf8",
        b"version = \xff",
        BootstrapEnvelopeError::Malformed,
    );
    require_refusal(
        "nul",
        b"version = 1\nstate_root = \"/srv/msgriver/data\0\"\n",
        BootstrapEnvelopeError::Malformed,
    );
    require_refusal(
        "oversize",
        "x".repeat(ENVELOPE_MAX_LEN + 1).as_bytes(),
        BootstrapEnvelopeError::Oversized,
    );
}
