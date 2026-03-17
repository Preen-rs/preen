use preen_core::{system_error_kind_label, system_localized_error_message};

#[test]
fn system_kind_label_supports_de_and_en_fallback() {
    assert_eq!(
        system_error_kind_label("unsupported", "de-DE"),
        "Nicht unterstuetzt"
    );
    assert_eq!(
        system_error_kind_label("unsupported", "en-US"),
        "Unsupported"
    );
    assert_eq!(
        system_error_kind_label("unsupported", "fr-FR"),
        "Unsupported"
    );
}

#[test]
fn system_detail_message_localizes_by_detail_code() {
    assert_eq!(
        system_localized_error_message(
            Some("clean_confirmation_required"),
            "clean apply mode requires --confirm",
            "de-DE"
        ),
        "Clean-Anwenden benoetigt --confirm."
    );
    assert_eq!(
        system_localized_error_message(
            Some("clean_confirmation_required"),
            "clean apply mode requires --confirm",
            "en-US"
        ),
        "Clean apply mode requires --confirm."
    );
    assert_eq!(
        system_localized_error_message(
            Some("command_not_implemented"),
            "uninstall command is not implemented yet",
            "de-DE"
        ),
        "uninstall Befehl ist noch nicht implementiert."
    );
}

#[test]
fn system_detail_message_falls_back_to_original_message() {
    let original = "arbitrary original error";
    assert_eq!(
        system_localized_error_message(Some("unknown_code"), original, "de-DE"),
        original
    );
}
