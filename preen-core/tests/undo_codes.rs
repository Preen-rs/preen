use preen_core::{
    UNDO_CODE_AMBIGUOUS, UNDO_CODE_GENERIC, UNDO_CODE_INFO_MISSING, UNDO_CODE_NOT_FOUND,
    UNDO_CODE_RESTORE_FAILED, classify_undo_error_code, undo_failed_user_message,
    undo_failed_user_message_with_language,
};

#[test]
fn classify_undo_error_code_maps_expected_patterns() {
    assert_eq!(
        classify_undo_error_code("ambiguous trash candidates for 1 (count=2)"),
        UNDO_CODE_AMBIGUOUS
    );
    assert_eq!(
        classify_undo_error_code("trash item not found for 1"),
        UNDO_CODE_NOT_FOUND
    );
    assert_eq!(
        classify_undo_error_code("trash restore failed: conflict"),
        UNDO_CODE_RESTORE_FAILED
    );
    assert_eq!(
        classify_undo_error_code("target path exists for 1"),
        UNDO_CODE_RESTORE_FAILED
    );
    assert_eq!(
        classify_undo_error_code("Cannot undo item 1 as no undo_info is available."),
        UNDO_CODE_INFO_MISSING
    );
    assert_eq!(
        classify_undo_error_code("some unknown undo error"),
        UNDO_CODE_GENERIC
    );
}

#[test]
fn undo_failed_user_message_maps_known_codes() {
    assert!(undo_failed_user_message(UNDO_CODE_AMBIGUOUS).contains("matching trash entries"));
    assert!(undo_failed_user_message(UNDO_CODE_NOT_FOUND).contains("not found"));
    assert!(undo_failed_user_message(UNDO_CODE_RESTORE_FAILED).contains("restore failed"));
    assert!(undo_failed_user_message(UNDO_CODE_INFO_MISSING).contains("metadata"));
    assert!(undo_failed_user_message("unknown_code").contains("Undo failed"));
}

#[test]
fn undo_failed_user_message_with_language_supports_en_de_and_fallback() {
    assert!(
        undo_failed_user_message_with_language(UNDO_CODE_NOT_FOUND, "en").contains("not found")
    );
    assert!(
        undo_failed_user_message_with_language(UNDO_CODE_NOT_FOUND, "de")
            .contains("nicht gefunden")
    );
    assert!(
        undo_failed_user_message_with_language(UNDO_CODE_NOT_FOUND, "fr").contains("not found")
    );
}
