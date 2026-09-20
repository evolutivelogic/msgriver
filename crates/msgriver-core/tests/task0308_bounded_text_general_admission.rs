//! Additive bounded text/title general admission contract, frozen before
//! Task 0308 GREEN.
//!
//! Every vector drives the public `check_text_content` seam with the explicit
//! default profile (`text_byte_limit = 4096`, `title_byte_limit = 256`). The
//! five admission groups stay outside every frozen literal; the final group
//! re-freezes the two unchanged no-title typed rejections.

use msgriver_core::RejectClass;

#[test]
fn ordinary_ascii_text_without_title_is_admitted() {
    assert_eq!(
        msgriver_core::bounded::check_text_content(
            b"deployment finished without intervention",
            None,
            4096,
            256,
        ),
        Ok(())
    );
}

#[test]
fn ordinary_ascii_text_and_title_are_admitted() {
    assert_eq!(
        msgriver_core::bounded::check_text_content(b"deploy finished", Some(b"status"), 4096, 256),
        Ok(())
    );
}

#[test]
fn non_ascii_utf8_body_without_title_is_admitted() {
    assert_eq!(
        msgriver_core::bounded::check_text_content(
            "Serviço concluído às nove".as_bytes(),
            None,
            4096,
            256,
        ),
        Ok(())
    );
}

#[test]
fn non_ascii_utf8_title_is_admitted() {
    assert_eq!(
        msgriver_core::bounded::check_text_content(
            b"backup running",
            Some("Résumé".as_bytes()),
            4096,
            256,
        ),
        Ok(())
    );
}

#[test]
fn interior_limit_neighbors_with_title_are_admitted() {
    let title = "B".repeat(255);
    assert_eq!(
        msgriver_core::bounded::check_text_content(
            b"report ready",
            Some(title.as_bytes()),
            4096,
            256,
        ),
        Ok(())
    );
    let text = "c".repeat(4_095);
    assert_eq!(
        msgriver_core::bounded::check_text_content(text.as_bytes(), Some(b"digest"), 4096, 256),
        Ok(())
    );
}

#[test]
fn unchanged_no_title_rejections_hold() {
    let too_long = "x".repeat(4_097);
    let error = msgriver_core::bounded::check_text_content(too_long.as_bytes(), None, 4096, 256)
        .expect_err("body beyond the default limit rejects without a title");
    assert_eq!(error.reject_class(), Some(RejectClass::TextTooLong));

    let error = msgriver_core::bounded::check_text_content(b"\xc3\x28", None, 4096, 256)
        .expect_err("invalid UTF-8 body without a title rejects");
    assert_eq!(error.reject_class(), Some(RejectClass::InvalidUtf8));
}
