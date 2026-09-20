//! Task 0250 byte-parser acceptance RED.

#![forbid(unsafe_code)]

use msgriver::bootstrap_envelope::{
    ENVELOPE_MAX_LEN, EnvelopeExpectation, RELEASE_ENVELOPE_PARENT, RELEASE_EXPECTATION,
    parse_envelope_v1,
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

fn expectation() -> EnvelopeExpectation<'static> {
    RELEASE_EXPECTATION
}

fn require_accepted(label: &str, bytes: &[u8]) {
    let envelope = parse_envelope_v1(bytes, expectation())
        .unwrap_or_else(|error| panic!("{label} must be accepted, got {error:?}"));
    assert_eq!(
        envelope.state_root().to_string_lossy(),
        "/srv/msgriver/data"
    );
}

#[test]
fn golden_closed_document_is_accepted() {
    require_accepted("golden", golden().as_bytes());
}

#[test]
fn equivalent_reordered_commented_and_literal_documents_are_accepted() {
    let reordered = concat!(
        "# release envelope\n",
        "resource_ceiling_profile = 'baseline-v1'\n",
        "socket_names = []\n",
        "credential_root = '/run/credentials/msgriver'\n",
        "service_user = 'msgriver'\n",
        "state_root = '/srv/msgriver/data'\n",
        "version = 1\n",
    );
    require_accepted("reordered-literal-commented", reordered.as_bytes());
}

#[test]
fn crlf_and_no_final_newline_are_accepted() {
    let crlf = golden().replace('\n', "\r\n");
    require_accepted("crlf", crlf.as_bytes());
    require_accepted("no-final-newline", golden().trim_end().as_bytes());
}

#[test]
fn exact_4096_byte_document_is_accepted() {
    let mut padded = golden();
    padded.push_str(&"#".repeat(ENVELOPE_MAX_LEN - padded.len()));
    assert_eq!(padded.len(), ENVELOPE_MAX_LEN);
    require_accepted("exact-4096", padded.as_bytes());
}

#[test]
fn release_constants_are_the_only_canonical_strings() {
    assert_eq!(RELEASE_ENVELOPE_PARENT, "/etc/msgriver");
    assert_eq!(RELEASE_EXPECTATION.state_root, "/srv/msgriver/data");
    assert_eq!(RELEASE_EXPECTATION.service_user, "msgriver");
    assert_eq!(
        RELEASE_EXPECTATION.credential_root,
        "/run/credentials/msgriver"
    );
    assert_eq!(RELEASE_EXPECTATION.resource_ceiling_profile, "baseline-v1");
}
