use preen_core::plugin::{parse_cli_json_envelope, parse_plugin_run_summary_from_cli_json};

#[test]
fn parses_plugin_test_summary() {
    let json = r#"{
  "schema_version": 1,
  "kind": "plugin.test",
  "data": {
    "overall_passed": true,
    "duration_ms": 12,
    "checks": [{ "check": "signature_verified", "passed": true }],
    "detail_code": "test_signature_or_trust_failed"
  }
}"#;
    let summary = parse_plugin_run_summary_from_cli_json(json).unwrap();
    assert!(summary.overall_passed);
    assert_eq!(summary.duration_ms, 12);
    assert_eq!(summary.checks.len(), 1);
    assert_eq!(
        summary.detail_code.as_deref(),
        Some("test_signature_or_trust_failed")
    );
}

#[test]
fn parses_plugin_preflight_summary_with_detail_code() {
    let json = r#"{
  "schema_version": 1,
  "kind": "plugin.preflight",
  "data": {
    "duration_ms": 9,
    "detail_code": "preflight_signature_or_trust_failed",
    "checks": [{ "check": "signature_verified", "passed": false }]
  }
}"#;
    let summary = parse_plugin_run_summary_from_cli_json(json).unwrap();
    assert!(!summary.overall_passed);
    assert_eq!(summary.duration_ms, 9);
    assert_eq!(
        summary.detail_code.as_deref(),
        Some("preflight_signature_or_trust_failed")
    );
}

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
    let summary = parse_plugin_run_summary_from_cli_json(json).unwrap();
    assert!(!summary.overall_passed);
    assert_eq!(summary.duration_ms, 0);
    assert_eq!(summary.detail_code.as_deref(), Some("test_all_failed"));
}

#[test]
fn parses_envelope_with_generic_data() {
    let json = r#"{
  "schema_version": 1,
  "kind": "plugin.preflight",
  "data": { "duration_ms": 7, "checks": [] }
}"#;
    let envelope = parse_cli_json_envelope(json).unwrap();
    assert_eq!(envelope.schema_version, 1);
    assert_eq!(envelope.kind, "plugin.preflight");
    assert_eq!(envelope.data["duration_ms"].as_u64(), Some(7));
}

#[test]
fn envelope_kind_roundtrip_supports_cli_kind_strings() {
    let json = r#"{
  "schema_version": 1,
  "kind": "plugin.test_all",
  "data": { "overall_passed": true }
}"#;
    let envelope = parse_cli_json_envelope(json).unwrap();
    assert_eq!(envelope.kind, "plugin.test_all");
}
