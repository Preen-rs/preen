pub use preen_core::plugin::parse_plugin_run_summary_from_cli_json as parse_summary_from_cli_json;
use preen_core::plugin::{
    PluginRunSummary, plugin_check_label, plugin_check_severity,
    plugin_failure_hint_from_detail_code, plugin_failure_hint_message,
};

pub fn summary_title(summary: &PluginRunSummary) -> String {
    summary_title_with_language(summary, "en-US")
}

pub fn summary_title_with_language(summary: &PluginRunSummary, language: &str) -> String {
    if summary.overall_passed {
        return format!("Plugin checks passed ({} ms)", summary.duration_ms);
    }
    if let Some(code) = &summary.detail_code {
        let hint = plugin_failure_hint_from_detail_code(code);
        return format!(
            "Plugin checks failed [{}] {} ({} ms)",
            code,
            plugin_failure_hint_message(hint.code, language),
            summary.duration_ms
        );
    }
    format!("Plugin checks failed ({} ms)", summary.duration_ms)
}

pub fn failed_checks(summary: &PluginRunSummary) -> Vec<String> {
    failed_checks_with_language(summary, "en-US")
}

pub fn failed_checks_with_language(summary: &PluginRunSummary, language: &str) -> Vec<String> {
    summary
        .checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| {
            let sev = plugin_check_severity(c.check).as_str();
            format!("[{}] {}", sev, plugin_check_label(c.check, language))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_summary_from_cli_json;

    #[test]
    fn parses_error_summary_with_detail_code() {
        let json = r#"{
  "schema_version": 1,
  "kind": "error",
  "data": {
    "error_kind": "verification",
    "detail_code": "test_all_failed",
    "message": "2 plugin test checks failed"
  }
}"#;
        let summary = parse_summary_from_cli_json(json).unwrap();
        assert!(!summary.overall_passed);
        assert_eq!(summary.duration_ms, 0);
        assert_eq!(summary.detail_code.as_deref(), Some("test_all_failed"));
        let title = super::summary_title_with_language(&summary, "de-DE");
        assert!(title.contains("Mindestens ein Plugin ist fehlgeschlagen"));
    }

    #[test]
    fn failed_checks_include_severity_and_label() {
        let json = r#"{
  "schema_version": 1,
  "kind": "plugin.test",
  "data": {
    "overall_passed": false,
    "duration_ms": 5,
    "checks": [
      { "check": "trust_verified", "passed": false }
    ]
  }
}"#;
        let summary = parse_summary_from_cli_json(json).unwrap();
        let failed = super::failed_checks(&summary);
        assert_eq!(failed, vec!["[critical] Trust verified".to_string()]);
        let failed_de = super::failed_checks_with_language(&summary, "de");
        assert_eq!(
            failed_de,
            vec!["[critical] Vertrauen verifiziert".to_string()]
        );
    }
}
