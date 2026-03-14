pub use preen_core::plugin::parse_plugin_run_summary_from_cli_json as parse_summary_from_cli_json;
use preen_core::plugin::{
    PluginRunSummary, plugin_check_label, plugin_check_severity,
    plugin_failure_hint_from_detail_code, plugin_failure_hint_message,
};

pub fn render_summary_lines(summary: &PluginRunSummary) -> Vec<String> {
    render_summary_lines_with_language(summary, "en-US")
}

pub fn render_summary_lines_with_language(
    summary: &PluginRunSummary,
    language: &str,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!("overall_passed: {}", summary.overall_passed));
    lines.push(format!("duration_ms: {}", summary.duration_ms));
    if let Some(code) = &summary.detail_code {
        lines.push(format!("detail_code: {code}"));
        let hint = plugin_failure_hint_from_detail_code(code);
        lines.push(format!(
            "hint: code={} action={} message={}",
            hint.code,
            hint.action,
            plugin_failure_hint_message(hint.code, language)
        ));
    }
    for check in &summary.checks {
        let severity = plugin_check_severity(check.check).as_str();
        lines.push(format!(
            "check [{}] {}={}",
            severity,
            plugin_check_label(check.check, language),
            check.passed
        ));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::parse_summary_from_cli_json;

    #[test]
    fn parses_plugin_test_summary() {
        let json = r#"{
  "schema_version": 1,
  "kind": "plugin.test",
  "data": {
    "overall_passed": true,
    "duration_ms": 12,
    "checks": [{ "check": "signature_verified", "passed": true }]
  }
}"#;
        let summary = parse_summary_from_cli_json(json).unwrap();
        assert!(summary.overall_passed);
        assert_eq!(summary.duration_ms, 12);
        assert_eq!(summary.checks.len(), 1);
    }

    #[test]
    fn maps_check_label_and_severity() {
        assert_eq!(
            preen_core::plugin::plugin_check_label(
                preen_core::plugin::PluginCheckId::TrustVerified,
                "en"
            ),
            "Trust verified"
        );
        assert_eq!(
            preen_core::plugin::plugin_check_label(
                preen_core::plugin::PluginCheckId::TrustVerified,
                "de"
            ),
            "Vertrauen verifiziert"
        );
        assert_eq!(
            preen_core::plugin::plugin_check_severity(
                preen_core::plugin::PluginCheckId::TrustVerified
            ),
            preen_core::plugin::PluginCheckSeverity::Critical
        );
    }

    #[test]
    fn renders_hint_line_for_error_detail_code() {
        let json = r#"{
  "schema_version": 1,
  "kind": "error",
  "data": {
    "error_kind": "verification",
    "detail_code": "preflight_os_target_failed",
    "message": "failed"
  }
}"#;
        let summary = parse_summary_from_cli_json(json).unwrap();
        let lines = super::render_summary_lines_with_language(&summary, "de-DE");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("hint: code=os_target_failed"))
        );
        assert!(lines.iter().any(|line| line.contains("Betriebssystem")));
    }
}
