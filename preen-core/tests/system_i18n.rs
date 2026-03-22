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

#[test]
fn system_detail_message_localizes_known_prefixed_detail_codes() {
    let original = "fallback message";
    let codes = [
        "purge_confirmation_required",
        "installer_path_scope_violation",
        "uninstall_command_timeout",
        "optimize_no_tasks",
        "analyze_root_not_found",
        "status_state_dir_unavailable",
        "completion_shell_unknown",
        "remove_path_resolve_failed",
    ];

    for code in codes {
        let en = system_localized_error_message(Some(code), original, "en-US");
        let de = system_localized_error_message(Some(code), original, "de-DE");
        assert_ne!(en, original, "missing en localization for {code}");
        assert_ne!(de, original, "missing de localization for {code}");
    }
}

#[test]
fn system_detail_message_ignores_unknown_prefixed_detail_codes() {
    let original = "fallback message";
    assert_eq!(
        system_localized_error_message(
            Some("unknownprefix_confirmation_required"),
            original,
            "en-US"
        ),
        original
    );
}
