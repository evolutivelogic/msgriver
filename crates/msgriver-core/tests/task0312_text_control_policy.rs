//! Additive decoded-scalar text control-character policy contract, frozen
//! before Task 0312 GREEN.
//!
//! Every vector drives the public `check_text_content` seam with the explicit
//! default profile (`text_byte_limit = 4096`, `title_byte_limit = 256`), a
//! non-empty interior-length body, and non-empty interior-length valid
//! companions. Each invalid vector carries exactly one control scalar and no
//! other invalid condition; non-default limits, length boundaries, oversized
//! values, and simultaneous invalid conditions stay at the bounded-grammar
//! frontier. Outcomes are frozen by stable reject label so this target
//! compiles before the new body-control reject class exists.

use msgriver_core::{CoreError, RejectClass};

const TEXT_LIMIT: u32 = 4096;
const TITLE_LIMIT: u32 = 256;
const VALID_BODY: &str = "deploy finished without intervention";
const VALID_TITLE: &str = "status";

fn check(text: &[u8], title: Option<&[u8]>) -> Result<(), CoreError> {
    msgriver_core::bounded::check_text_content(text, title, TEXT_LIMIT, TITLE_LIMIT)
}

fn body_control_scalars() -> impl Iterator<Item = char> {
    ('\u{0000}'..='\u{0008}')
        .chain('\u{000B}'..='\u{000C}')
        .chain('\u{000E}'..='\u{001F}')
        .chain('\u{007F}'..='\u{009F}')
}

fn title_control_scalars() -> impl Iterator<Item = char> {
    ('\u{0000}'..='\u{001F}').chain('\u{007F}'..='\u{009F}')
}

fn assert_invalid_text_control(scalar: char) {
    let error = check(format!("a{scalar}b").as_bytes(), None)
        .expect_err("disallowed body control rejects without a title");
    assert_eq!(
        error.reject_class().map(RejectClass::label),
        Some("invalid_text_control"),
        "body scalar U+{:04X}",
        scalar as u32
    );
}

fn assert_invalid_title_control(scalar: char) {
    let title = format!("a{scalar}b");
    let error = check(VALID_BODY.as_bytes(), Some(title.as_bytes()))
        .expect_err("disallowed title control rejects over a valid body");
    assert_eq!(
        error.reject_class().map(RejectClass::label),
        Some("invalid_title_control"),
        "title scalar U+{:04X}",
        scalar as u32
    );
}

#[test]
fn body_c0_and_c1_controls_reject_without_title() {
    for scalar in body_control_scalars() {
        assert_invalid_text_control(scalar);
    }
}

#[test]
fn title_c0_and_c1_controls_reject_over_valid_body() {
    for scalar in title_control_scalars() {
        assert_invalid_title_control(scalar);
    }
}

#[test]
fn multiline_body_whitespace_is_admitted_with_and_without_title() {
    let multiline_bodies: [&[u8]; 4] = [
        b"line one\tline two",
        b"line one\nline two",
        b"line one\rline two",
        b"line one\r\nline two",
    ];
    for body in multiline_bodies {
        assert_eq!(
            check(body, None),
            Ok(()),
            "multiline body {:?} without a title",
            String::from_utf8_lossy(body)
        );
        assert_eq!(
            check(body, Some(VALID_TITLE.as_bytes())),
            Ok(()),
            "multiline body {:?} with a valid title",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn body_control_neighbors_split_at_each_range_edge() {
    for scalar in ['\u{0008}', '\u{000E}', '\u{001F}', '\u{007F}', '\u{009F}'] {
        assert_invalid_text_control(scalar);
    }
    for scalar in [
        '\u{0009}', '\u{000D}', '\u{0020}', '\u{007E}', '\u{00A0}', '\u{0100}',
    ] {
        let body = format!("a{scalar}b");
        assert_eq!(
            check(body.as_bytes(), None),
            Ok(()),
            "body scalar U+{:04X} without a title",
            scalar as u32
        );
        assert_eq!(
            check(body.as_bytes(), Some(VALID_TITLE.as_bytes())),
            Ok(()),
            "body scalar U+{:04X} with a valid title",
            scalar as u32
        );
    }
}

#[test]
fn title_control_neighbors_split_at_each_range_edge() {
    for scalar in [
        '\u{0008}', '\u{0009}', '\u{000D}', '\u{000E}', '\u{001F}', '\u{007F}', '\u{009F}',
    ] {
        assert_invalid_title_control(scalar);
    }
    for scalar in ['\u{0020}', '\u{007E}', '\u{00A0}', '\u{0100}'] {
        let title = format!("a{scalar}b");
        assert_eq!(
            check(VALID_BODY.as_bytes(), Some(title.as_bytes())),
            Ok(()),
            "title scalar U+{:04X} over a valid body",
            scalar as u32
        );
    }
}
