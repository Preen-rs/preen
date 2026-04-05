use preen_core::plugin::{
    PluginCheckId, PluginCheckStatus, PluginDetailCode, PluginTestDrift, plugin_check_label,
    plugin_error_kind_label, plugin_failure_hint_context_from_detail_code,
    plugin_failure_hint_from_detail_code, plugin_failure_hint_message,
    plugin_localized_error_message, plugin_primary_failure_hint_from_drifts,
};

#[test]
fn plugin_check_id_serializes_as_stable_snake_case() {
    let row = PluginCheckStatus::new(PluginCheckId::CoreCompatVerified, true);
    let encoded = serde_json::to_string(&row).unwrap();
    assert!(encoded.contains("\"check\":\"core_compat_verified\""));
    assert!(encoded.contains("\"passed\":true"));
}

#[test]
fn plugin_detail_code_source_checkout_taxonomy_is_parseable_and_stable() {
    let code = PluginDetailCode::InstallSourceFetchFailed;
    assert_eq!(code.as_str(), "install_source_fetch_failed");
    assert_eq!(
        PluginDetailCode::parse("install_source_fetch_failed"),
        Some(PluginDetailCode::InstallSourceFetchFailed)
    );
    assert_eq!(
        PluginDetailCode::parse("preflight_source_checkout_failed"),
        Some(PluginDetailCode::PreflightSourceCheckoutFailed)
    );
    assert_eq!(PluginDetailCode::parse("unknown"), None);
}

#[test]
fn plugin_check_label_supports_en_de_and_fallback() {
    assert_eq!(
        plugin_check_label(PluginCheckId::TrustVerified, "en"),
        "Trust verified"
    );
    assert_eq!(
        plugin_check_label(PluginCheckId::TrustVerified, "de"),
        "Vertrauen verifiziert"
    );
    assert_eq!(
        plugin_check_label(PluginCheckId::TrustVerified, "fr"),
        "Trust verified"
    );
}

#[test]
fn plugin_failure_hint_supports_mapping_and_locale_message() {
    let hint = plugin_failure_hint_from_detail_code("preflight_action_api_unsupported");
    assert_eq!(hint.code, "action_api_unsupported");
    assert_eq!(hint.priority, 1);

    let de = plugin_failure_hint_message(hint.code, "de-DE");
    assert!(de.contains("Action-API"));
    let en = plugin_failure_hint_message(hint.code, "en-US");
    assert!(en.contains("action API"));

    let verify_hint = plugin_failure_hint_from_detail_code("verify_manifest_hash_drift");
    assert_eq!(verify_hint.code, "manifest_hash_drift");
    assert_eq!(verify_hint.priority, 2);

    let action_type_hint = plugin_failure_hint_from_detail_code("verify_action_type_unsupported");
    assert_eq!(action_type_hint.code, "action_type_unsupported");
    assert_eq!(action_type_hint.priority, 1);

    let test_hint = plugin_failure_hint_from_detail_code("test_signature_or_trust_failed");
    assert_eq!(test_hint.code, "trust_or_signature_failed");
    assert_eq!(test_hint.priority, 0);

    let load_hint = plugin_failure_hint_from_detail_code("verify_pack_load_failed");
    assert_eq!(load_hint.code, "pack_load_failed");
    assert_eq!(load_hint.priority, 2);

    let clone_hint = plugin_failure_hint_from_detail_code("install_source_fetch_failed");
    assert_eq!(clone_hint.code, "source_checkout_failed");
    assert_eq!(clone_hint.priority, 2);

    let context =
        plugin_failure_hint_context_from_detail_code("install_source_fetch_failed", "en-US");
    assert_eq!(context.code, "source_checkout_failed");
    assert_eq!(context.action, "validate_git_url_and_pinned_rev");
    assert!(context.message.contains("Git checkout failed"));

    let context_de =
        plugin_failure_hint_context_from_detail_code("preflight_source_checkout_failed", "de-DE");
    assert_eq!(context_de.code, "source_checkout_failed");
    assert_eq!(context_de.action, "validate_git_url_and_pinned_rev");
    assert!(context_de.message.contains("Git-Checkout"));
}

#[test]
fn plugin_primary_failure_hint_uses_highest_priority() {
    let drifts = vec![
        PluginTestDrift {
            field: "version".to_string(),
            expected: "1.0.0".to_string(),
            actual: "2.0.0".to_string(),
        },
        PluginTestDrift {
            field: "signature_or_trust".to_string(),
            expected: "verified".to_string(),
            actual: "invalid".to_string(),
        },
    ];
    let hint = plugin_primary_failure_hint_from_drifts(&drifts).unwrap();
    assert_eq!(hint.code, "trust_or_signature_failed");
    assert_eq!(hint.priority, 0);
}

#[test]
fn plugin_localized_error_message_uses_detail_code_and_fallback() {
    let de = plugin_localized_error_message(
        Some("preflight_os_target_failed"),
        "unsupported os target",
        "de-DE",
    );
    assert!(de.contains("Betriebssystem"));

    let en = plugin_localized_error_message(None, "plugin not found", "en-US");
    assert!(en.contains("Plugin not found"));

    let install_source = plugin_localized_error_message(
        Some("install_source_checkout_failed"),
        "checkout failed",
        "en-US",
    );
    assert!(install_source.contains("Git checkout failed"));

    let action_type = plugin_localized_error_message(
        Some("verify_action_type_unsupported"),
        "unsupported action type",
        "en-US",
    );
    assert!(action_type.contains("action types unsupported"));

    let passthrough = plugin_localized_error_message(None, "custom failure", "de-DE");
    assert_eq!(passthrough, "custom failure");
}

#[test]
fn plugin_localized_error_message_supports_new_source_checkout_detail_codes_en_de() {
    let source_codes = [
        "install_source_clone_failed",
        "install_source_fetch_failed",
        "install_source_checkout_failed",
        "install_source_git_resolve_failed",
        "preflight_source_clone_failed",
        "preflight_source_fetch_failed",
        "preflight_source_checkout_failed",
        "preflight_source_git_resolve_failed",
    ];
    for code in source_codes {
        let en = plugin_localized_error_message(Some(code), "source failure", "en-US");
        assert!(
            en.contains("Git checkout failed"),
            "missing en localization for {code}"
        );
        let de = plugin_localized_error_message(Some(code), "source failure", "de-DE");
        assert!(
            de.contains("Git-Checkout"),
            "missing de localization for {code}"
        );
    }
}

#[test]
fn plugin_error_kind_label_supports_en_de_and_fallback() {
    assert_eq!(plugin_error_kind_label("trust", "en-US"), "Trust");
    assert_eq!(plugin_error_kind_label("trust", "de-DE"), "Vertrauen");
    assert_eq!(plugin_error_kind_label("unknown-kind", "en-US"), "Internal");
}
